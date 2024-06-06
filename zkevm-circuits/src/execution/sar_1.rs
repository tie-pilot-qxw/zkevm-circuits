use crate::arithmetic_circuit::operation;

use crate::execution::{
    sar_2, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{
    arithmetic, assign_or_panic, get_and_insert_shl_shr_rows, Witness, WitnessExecHelper,
};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = 0;
const PC_DELTA: u64 = 0;
const SHIFT_MAX: u8 = 255;

pub(crate) const SIGN_BIT_IS_ZERO_CELL_IDX: usize = 29;
pub(crate) const SHL_RESULT_HI_CELL_IDX: usize = 30;
pub(crate) const SHL_RESULT_LO_CELL_IDX: usize = 31;
pub(crate) const V_2: u8 = 2;

/// Algorithm overview:
///  the SAR instruction is a signed right shift
///  the implementation of the SAR instruction is split into two steps: SAR1 and SAR2
///  SAR1:
///    SAR1 performs an unsigned right shift of the operands (refer to SHR instruction implementation)
///  SAR2:
///    use the 255-shift value as the sign to perform sign bit extension on the results obtained by SAR1 (refer to the SIGNEXTEND instruction for implementation)
///
/// example:
///  value: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0
///  shift: 4
///  exec SAR1:
///    unsigned right shift by four bits: 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
///  exec SAR2:
///    the value of the 251st bit of the result of SAR1 is 1, use 1 as the sign bit to perform sign bit extension on the result of SAR1.
///    get the result: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
///    
///
/// SAR1 Table layout:
/// +---+-------+-------+-----------+--------------------------+
/// |cnt| 8 col | 8 col |  8 col    |  8 col                   |
/// +---+-------+-------+-----------+--------------------------+
/// | 2 | ARITH0 | ARITH1| ARITH2   |                          |
/// | 1 | STATE0|STATE1|            |     EXP                  |
/// | 0 | DYNA_SELECTOR   | AUX     | SIGN_BIT, RES_HI, RES_LO |
/// +---+-------+-------+-------+---+--------------------------+
/// ARITH0 Arithmetic(Sub) lookup, 9 columns
/// ARITH1 Arithmetic-Div(SAR) lookup, 9 columns
/// STATE0: operand_0 lookup, 8 columns
/// STATE1: operand_1 lookup, 8 columns
/// SIGN_BIT: sign_bit_is_zero(if sign bit is 0 then sign_bit_is_zero is 1, if sign bit is 1 then sign_bit_is_zero is 0), 1 column
/// RES_HI: SAR1 result hi, 1 column
/// RES_HI: SAR1 result lo, 1 column
/// EXP: exp lookup, 6 columns
pub struct Sar1Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Sar1Gadget<F>
{
    fn name(&self) -> &'static str {
        "SAR_1"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SAR_1
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, sar_2::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-OpcodeId::SAR.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        // stack constraints
        let mut stack_operands = vec![];
        let stack_pointer_delta = vec![0, -1];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                false,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        // get sign_bit_is_zero ans result
        let sign_bit_is_zero =
            meta.query_advice(config.vers[SIGN_BIT_IS_ZERO_CELL_IDX], Rotation::cur());
        let result_hi = meta.query_advice(config.vers[SHL_RESULT_HI_CELL_IDX], Rotation::cur());
        let result_lo = meta.query_advice(config.vers[SHL_RESULT_LO_CELL_IDX], Rotation::cur());

        stack_operands.push([result_hi, result_lo]);

        let (sub_tag, sub_arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));
        let (mul_div_tag, mul_div_arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 1));
        // stack_value - 2^255
        let (sign_bit_sub_tag, sign_bit_sub_arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 2));

        // sub arithmetic constraints
        constraints.extend(config.get_shl_shr_sar1_sub_arith_constraints(
            &stack_operands[0],
            &mul_div_arithmetic_operands,
            &sub_arithmetic_operands,
        ));

        // mul_div_arithmetic constraints
        constraints.extend(config.get_shl_shr_sar1_mul_div_arith_constraints(
            &stack_operands[1],
            &stack_operands[2],
            &mul_div_arithmetic_operands,
        ));

        // exp constraints
        constraints.extend(config.get_shl_shr_sar1_exp_constraints(
            meta,
            &stack_operands[0],
            &mul_div_arithmetic_operands,
        ));

        // constrain sign_bit_is_zero
        constraints.extend([
            (
                "calc sign bit arithmetic tag is Sub".into(),
                sign_bit_sub_tag - (arithmetic::Tag::Sub as u8).expr(),
            ),
            (
                "calc sign bit arithmetic operand0 hi = stack value hi".into(),
                sign_bit_sub_arithmetic_operands[0].clone() - stack_operands[1][0].clone(),
            ),
            (
                "calc sign bit arithmetic operand0 lo = stack value lo".into(),
                sign_bit_sub_arithmetic_operands[1].clone() - stack_operands[1][1].clone(),
            ),
            (
                "calc sign bit arithmetic operand1 hi = 2^255 hi".into(),
                sign_bit_sub_arithmetic_operands[2].clone() - 1.expr() * pow_of_two::<F>(127),
            ),
            (
                "calc sign bit arithmetic operand1 lo = 2^255 lo(is zero)".into(),
                sign_bit_sub_arithmetic_operands[3].clone(),
            ),
            // if stack_value >= 2^55, then sign_bit is 1 and sign_bit_is_zero is 0, arithmetic_carry is 0
            // if stack_value < 2^55, then sign_bit is 0 and sign_bit_is_zero is 1, arithmetic_carry is 1
            (
                "calc sign bit arithmetic carry = sign_bit_is_zero".into(),
                sign_bit_sub_arithmetic_operands[6].clone() - sign_bit_is_zero,
            ),
        ]);

        // constrain Opcode
        // opcode is SAR
        // arithmetic tag is DivMod,
        constraints.extend([
            (
                "opcode must be sar".into(),
                opcode.clone() - OpcodeId::SAR.as_u8().expr(),
            ),
            (
                "opcode is sar ==> mul_div_arithmetic tag is div".into(),
                mul_div_tag - (arithmetic::Tag::DivMod as u8).expr(),
            ),
            (
                "sub arithmetic tag".into(),
                sub_tag - (arithmetic::Tag::Sub as u8).expr(),
            ),
        ]);

        // next execution is SAR_2
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::SAR_2, sar_2::NUM_ROW, None)],
                None,
            ),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // exp lookup
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        // stack lookup
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        // sub arithmetic lookup
        let sub_arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        // mul_div arithmetic lookup
        let mul_div_arithmetic =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 1));

        let sign_bit_sub_arithmetic =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 2));

        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("exp lookup".into(), exp_lookup),
            ("arithmetic sub lookup".into(), sub_arithmetic),
            ("arithmetic mul_div lookup".into(), mul_div_arithmetic),
            (
                "sign bit arithmetic sub lookup".into(),
                sign_bit_sub_arithmetic,
            ),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::SAR);

        // peek two elements from the top of the stack: shift, value
        let (stack_read_0, stack_shift) = current_state.get_peek_stack_row_value(&trace, 1);
        let (stack_read_1, stack_value) = current_state.get_peek_stack_row_value(&trace, 2);

        // calc result
        let result = if stack_shift > SHIFT_MAX.into() {
            0.into()
        } else {
            stack_value >> stack_shift
        };
        // calc sar1 result
        let result_hi = result >> 128;
        let result_lo = U256::from(result.low_u128());

        // calc sign bit
        //  if value minus 2^255 is greater than 0, it means that the 256th bit of value, the sign bit, has a value of 1, otherwise it is 0
        let power_of_255 = U256::from(V_2).pow(U256::from(SHIFT_MAX));
        let sign_bit_is_zero = if stack_value > power_of_255 {
            U256::zero()
        } else {
            U256::one()
        };
        current_state.sar = Some((result, sign_bit_is_zero));

        let (arithmetic_sub_rows, _) = operation::sub::gen_witness(vec![stack_value, power_of_255]);

        // Construct core_row_2,core_row_1,core_row_0  object
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        let mut core_row_0 = ExecutionState::SAR_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // insert state lookup, operand_0,operand_1,final_result
        core_row_1.insert_state_lookups([&stack_read_0, &stack_read_1]);

        // get and insert shl or shr rows
        let (mut arithmetic_rows, exp_rows) = get_and_insert_shl_shr_rows::<F>(
            stack_shift,
            stack_value,
            OpcodeId::SHR,
            &mut core_row_1,
            &mut core_row_2,
        );
        core_row_2.insert_arithmetic_lookup(2, &arithmetic_sub_rows);

        // assign shr result
        assign_or_panic!(core_row_0[SIGN_BIT_IS_ZERO_CELL_IDX], sign_bit_is_zero);
        assign_or_panic!(core_row_0[SHL_RESULT_HI_CELL_IDX], result_hi);
        assign_or_panic!(core_row_0[SHL_RESULT_LO_CELL_IDX], result_lo);

        arithmetic_rows.extend(arithmetic_sub_rows);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_read_0, stack_read_1],
            exp: exp_rows,
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Sar1Gadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    fn run(opcode: OpcodeId, stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: 0x254023u64,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + opcode.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, opcode, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::SAR_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sar_normal() {
        // sar num normal,index normal
        let stack = Stack::from_slice(&[2.into(), 1.into()]);
        run(OpcodeId::SAR, stack, U256::from(1))
    }

    #[test]
    fn test_sar_normal_max() {
        // sar num normal, index max
        let stack = Stack::from_slice(&[0xFF.into(), 255.into()]);
        run(OpcodeId::SAR, stack, U256::from(0))
    }

    #[test]
    fn test_sar_max() {
        // sar  num max , index max
        let stack = Stack::from_slice(&[U256::MAX, 255.into()]);
        run(OpcodeId::SAR, stack, U256::from(1))
    }

    #[test]
    fn test_sar_max_overflow() {
        // sar index overflow
        let stack = Stack::from_slice(&[U256::MAX, 256.into()]);
        run(OpcodeId::SAR, stack, U256::from(0))
    }
}
