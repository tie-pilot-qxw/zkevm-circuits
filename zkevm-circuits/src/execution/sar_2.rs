use crate::execution::{
    sar_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::exp;
use crate::witness::{get_and_insert_signextend_rows, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_POINTER_DELTA: i32 = 1;

const STATE_STAMP_DELTA: u64 = 2;
const BIT_MAX_INDEX: u8 = 255;

const EXP_BASE: u8 = 2;

/// SAR2 Table layout
/// +---+---------+---------+-------------------------------+-------------+
/// |cnt| 8 col   | 8 col   | 8 col  |               8 col                |
/// +---+---------+---------+-------------------------------+-------------+
/// | 2 | ARITH     |  BW0 |  BW1  |  BW2  |   BW3          |             |  
/// | 1 | STATE0 | STATE1  |                         EXP        |
/// | 0 |       DYNA_SELECTOR   | AUX   | A_HI | A_LO |D_HI |D_LO |NZ_INV |                        
/// +---+---------+---------+-------------------------------+-------------+
pub struct Sar2Gadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Sar2Gadget<F>
{
    fn name(&self) -> &'static str {
        "SAR_2"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SAR_2
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_POINTER_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        // [shift_hi,shift_lo,result_hi,result_lo]
        let mut stack_operands = vec![];
        let stack_pointer_delta = vec![0, -1];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            // stack constraints
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                i == 1,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        let sar1_sign_bit_is_zero = meta.query_advice(
            config.vers[sar_1::SIGN_BIT_IS_ZERO_CELL_INDEX],
            Rotation(-1 * (NUM_ROW as i32)),
        );
        let sar1_result_hi = meta.query_advice(
            config.vers[sar_1::SHL_RESULT_HI_CELL_INDEX],
            Rotation(-1 * (NUM_ROW as i32)),
        );
        let sar1_result_lo = meta.query_advice(
            config.vers[sar_1::SHL_RESULT_LO_CELL_INDEX],
            Rotation(-1 * (NUM_ROW as i32)),
        );

        // get signextend operands
        let (
            signextend_a_hi,
            signextend_a_lo,
            signextend_d_hi,
            signextend_d_lo,
            sign_bit_is_zero_inv,
        ) = config.get_signextend_operands(meta);

        // get bitwise_lookups and sign_bit_is_zero
        let (bitwise_lookups, sign_bit_is_zero) =
            config.get_signextend_bitwise_lookups(meta, sign_bit_is_zero_inv);

        constraints.extend(sign_bit_is_zero.get_constraints());

        // calc sign_bit_is_one
        let sign_bit_is_one = 1.expr() - sign_bit_is_zero.expr();

        // constrain arithmetic
        // arithmetic_operands[0] is 0
        // arithmetic_operands[1] is 255
        // arithmetic_operands[2] is stack_top0_hi(shift)
        // arithmetic_operands[3] is stack_top0_lo(shift)
        // arithmetic_tag is Sub
        let (arithmetic_constraints, shift_gt_255) = config.get_signextend_sub_arith_constraints(
            meta,
            stack_operands[0].clone().to_vec(),
            BIT_MAX_INDEX.expr(),
        );
        constraints.extend(arithmetic_constraints);

        // constrain exp
        let exp_entry = config.get_exp_lookup(meta);
        let (base, index, pow) = extract_lookup_expression!(exp, exp_entry);
        constraints.extend([
            ("base hi".into(), base[0].clone()),
            ("base lo".into(), base[1].clone() - EXP_BASE.expr()),
            (
                "pow[0] = a_hi".into(),
                pow[0].clone() - signextend_a_hi.clone(),
            ),
            (
                "pow[1] = a_lo".into(),
                pow[1].clone() - signextend_a_lo.clone(),
            ),
            ("index hi = 0".into(), index[0].clone()),
            (
                "shift <= 255 => index_lo = 255-stack_top0 lo(shift)".into(),
                (1.expr() - shift_gt_255.clone())
                    * (index[1].clone() - (BIT_MAX_INDEX.expr() - stack_operands[0][1].clone())),
            ),
            (
                "shift > 255 => index_lo=255".into(),
                shift_gt_255.clone() * (index[1].clone() - BIT_MAX_INDEX.expr()),
            ),
        ]);

        // singextend operand1:
        // if shift > 255 and sign bit is one, then signextend operand1 hi is u128::Max and signextend operand1 lo is u128::Max
        // if shift > 255 and sign bit is zero, then signextend operand1 hi is 0 and signextend operand1 lo is 0
        // if shift <= 255 then signextend operand1 hi is stack_top1 hi and signextend operand1 lo is stack_top1 lo
        let shift_gt_255_sign_bit_is_one_value =
            shift_gt_255.clone() * sign_bit_is_one.clone() * u128::MAX.expr();
        let shift_gt_255_sign_bit_is_zero_value =
            shift_gt_255.clone() * sign_bit_is_zero.expr() * 0.expr();
        let shift_le_255 = 1.expr() - shift_gt_255.clone();

        let signextend_operand1 = [
            shift_gt_255_sign_bit_is_one_value.clone()
                + shift_gt_255_sign_bit_is_zero_value.clone()
                + shift_le_255.clone() * sar1_result_hi.clone(),
            shift_gt_255_sign_bit_is_one_value.clone()
                + shift_gt_255_sign_bit_is_zero_value.clone()
                + shift_le_255.clone() * sar1_result_lo.clone(),
        ];

        // signextend result:
        // if shift > 255 and sign bit is one, then signextend result hi is u128::Max and signextend result lo is u128::Max
        // if shift > 255 and sign bit is zero, then signextend result hi is 0 and signextend result lo is 0
        // if shift <= 255 then signextend operand1 hi is stack_push hi and signextend operand1 lo is stack_push lo
        let signextend_expect_result = [
            shift_gt_255_sign_bit_is_one_value.clone()
                + shift_gt_255_sign_bit_is_zero_value.clone()
                + shift_le_255.clone() * stack_operands[1][0].clone(),
            shift_gt_255_sign_bit_is_one_value.clone()
                + shift_gt_255_sign_bit_is_zero_value.clone()
                + shift_le_255.clone() * stack_operands[1][1].clone(),
        ];

        // constrain bitwises
        constraints.extend(config.get_signextend_bitwise_constraints(
            bitwise_lookups,
            [signextend_a_hi, signextend_a_lo],
            signextend_operand1,
            [signextend_d_hi, signextend_d_lo],
            signextend_expect_result,
            sign_bit_is_zero.expr(),
            // When performing bitwise calculation of signextend, the maximum shift value is 255, and there is no situation exceeding 255.
            0.expr(),
        ));

        // constrain sign bit
        // the value of the sign bit must be equal to the value of the sign bit calculated in sar1
        constraints.extend([(
            "sign bit value must be equal sign bit calc in sar1  ".into(),
            sar1_sign_bit_is_zero - sign_bit_is_zero.expr(),
        )]);

        // constrain stack push value
        constraints.extend([
            (
                "shift_gt_255 = 1 and sign_bit = 1 ==> stack push hi=0xfffff...fff(32f)".into(),
                shift_gt_255.clone()
                    * sign_bit_is_one.clone()
                    * (stack_operands[1][0].clone() - u128::MAX.expr()),
            ),
            (
                "shift_gt_255 = 1 and sign_bit = 1 ==> stack push lo=0xfffff...fff(32f)".into(),
                shift_gt_255.clone()
                    * sign_bit_is_one.clone()
                    * (stack_operands[1][1].clone() - u128::MAX.expr()),
            ),
            (
                "shift_gt_255 = 1 and sign_bit = 0 ==> stack push hi =0".into(),
                shift_gt_255.clone() * sign_bit_is_zero.expr() * stack_operands[1][0].clone(),
            ),
            (
                "shift_gt_255 = 1 and sign_bit = 0 ==> stack push lo =0".into(),
                shift_gt_255.clone() * sign_bit_is_zero.expr() * stack_operands[1][1].clone(),
            ),
        ]);

        // constrain opcode
        constraints.extend([(
            "opcode must be SAR".into(),
            opcode.clone() - OpcodeId::SAR.as_u8().expr(),
        )]);

        // prev execution is SAR_1
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::SAR_1], NUM_ROW, vec![]),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        //  add bitwise lookups
        let bitwise_lookup_0 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 0));
        let bitwise_lookup_1 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 1));
        let bitwise_lookup_2 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 2));
        let bitwise_lookup_3 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 3));
        // arithmetic lookup
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        vec![
            ("stack pop operand_0".into(), stack_lookup_0),
            ("stack push result".into(), stack_lookup_1),
            ("exp result".into(), exp_lookup),
            ("bitwise lookup 0".into(), bitwise_lookup_0),
            ("bitwise lookup 1".into(), bitwise_lookup_1),
            ("bitwise lookup 2".into(), bitwise_lookup_2),
            ("bitwise lookup 3".into(), bitwise_lookup_3),
            ("arithmetic lookup 0".into(), arithmetic_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::SAR);
        // peek one element from the top of the stack
        let (stack_pop_0, shift) = current_state.get_pop_stack_row_value(trace);
        current_state.stack_pointer_decrease();

        // get sar1 result and value sign bit
        let (sra1_result, sign_bit_is_zero) = current_state.sar.unwrap();
        // reset sra_temp_val
        current_state.sar = None;

        // get state push row
        let result = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, result);

        // used to determine whether bit_idx is greater than bit_idx_max
        let bit_max_index = U256::from(BIT_MAX_INDEX);

        // if shift <= 255 and sign_bit is 1, then signextend_operand1 is stack top 1 and exp index is 255-shift
        // if shift > 255 and sign_bit is 1, then signextend_operand1 is U256::MAX and exp index is 255, stack_push is U256::max
        // if shift > 255 and sign_bit is 0, then signextend_operand1 is 0 and exp index is 255, stack_push is 0
        let (signextend_operand1, exp_index) = if shift <= bit_max_index {
            (sra1_result, bit_max_index - shift)
        } else {
            // if the sign_bit_is_zero value is 0, it means that the sign bit value of value is 1
            // if the sign_bit_is_zero value is 1, it means that the sign bit value of value is 0
            if sign_bit_is_zero.is_zero() {
                assert_eq!(U256::MAX, result);
                (U256::MAX, bit_max_index)
            } else {
                assert_eq!(U256::zero(), result);
                (U256::zero(), bit_max_index)
            }
        };

        // get exp_rows
        let exp_base = U256::from(EXP_BASE);
        let (calc_exp_power, exp_rows, exp_arith_mul_rows) =
            exp::Row::from_operands(exp_base, exp_index);

        // construct core_row_2,core_row_1,core_row_0  object
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        let mut core_row_0 = ExecutionState::SAR_2.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // insert state lookup to core_row_1
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(exp_base, exp_index, calc_exp_power);

        // get signextend related rows
        let (bitwise_rows, arithmetic_sub_rows) = get_and_insert_signextend_rows::<F>(
            [calc_exp_power, signextend_operand1], // signextend_a, signextend_operand1
            [bit_max_index, shift],
            &mut core_row_0,
            &mut core_row_1,
            &mut core_row_2,
        );

        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(arithmetic_sub_rows);
        arithmetic_rows.extend(exp_arith_mul_rows);
        // Construct witness  object
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_push_0],
            exp: exp_rows,
            bitwise: bitwise_rows,
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Sar2Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    const SIGN_BIT_COLUMN_ID: usize = 29;
    const SAR1_HI_COLUMN_ID: usize = 30;
    const SAR1_LO_COLUMN_ID: usize = 31;

    fn run(value_sign_bit_is_zero: U256, sar1_result: U256, stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(stack_top),
            sar: Some((sar1_result, value_sign_bit_is_zero)),
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, OpcodeId::SAR, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::SAR_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[21] = Some(stack_pointer.into());
            row[SIGN_BIT_COLUMN_ID] = Some(value_sign_bit_is_zero);
            row[SAR1_HI_COLUMN_ID] = Some(sar1_result >> 128);
            row[SAR1_LO_COLUMN_ID] = Some(sar1_result.low_u128().into());
            row
        };

        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);

        witness.print_csv();
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_normal() {
        let stack = Stack::from_slice(&[0xff.into(), 33.into()]);
        let value_sign_bit_is_zero = U256::one();
        let sar1_result = 0xff.into();
        let expect_result = U256::from(0xff);
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }

    #[test]
    fn test_shift_0() {
        let value = U256::from_str_radix(
            "0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            16,
        )
        .unwrap();
        let stack = Stack::from_slice(&[value, 0.into()]);

        let value_sign_bit_is_zero = U256::one();
        let sar1_result = value;

        let expect_result = value;

        // run
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }

    #[test]
    fn test_normal2() {
        let value = U256::from_str_radix(
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
            16,
        )
        .unwrap();
        let stack = Stack::from_slice(&[value, 4.into()]);

        let value_sign_bit_is_zero = U256::zero();
        let sar1_result = U256::from_str_radix(
            "0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            16,
        )
        .unwrap();

        let expect_result = U256::from_str_radix(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            16,
        )
        .unwrap();

        // run
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }

    #[test]
    fn test_shift_gt_255() {
        let value = 0xFF.into();
        let stack = Stack::from_slice(&[value, 257.into()]);

        let value_sign_bit_is_zero = U256::one();
        let sar1_result = U256::zero();

        let expect_result = U256::zero();

        // run
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }

    #[test]
    fn test_shift_gt_255_2() {
        let value = 0xFF.into();
        let stack = Stack::from_slice(&[value, U256::MAX]);

        let value_sign_bit_is_zero = U256::one();
        let sar1_result = U256::zero();

        let expect_result = U256::zero();

        // run
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }

    #[test]
    fn test_shift_gt_255_3() {
        let value = U256::from_str_radix(
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
            16,
        )
        .unwrap();
        let stack = Stack::from_slice(&[value, 257.into()]);

        let value_sign_bit_is_zero = U256::zero();
        let sar1_result = U256::zero();

        let expect_result = U256::from_str_radix(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            16,
        )
        .unwrap();

        // run
        run(value_sign_bit_is_zero, sar1_result, stack, expect_result);
    }
}
