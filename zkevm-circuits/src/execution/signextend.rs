use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
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

const NUM_ROW: usize = 3;
const STACK_POINTER_DELTA: i32 = -1;
const STATE_STAMP_DELTA: u64 = 3;
const BYTE_MAX_IDX: u8 = 31;
const EXP_BASE: usize = 256;
const V_128: u8 = 128;

/// Signextend gadget
/// algorithm:
/// let operand_0 , operand_1 on stack top,top-1;
/// 1. get a :  a = 128 * 256^operand_0
/// 2. get not_is_zero :
///     2.1) let temp_sum = operand_1 & a;
///     2.2) let not_is_zero = sum(temp_sum.as_bytes())/128;
/// 3. get b_lo :
///     if a_lo == 0,then b_lo = 2^128 -1;
///     if a_lo <> 0, then b_lo  = 2*a_lo -1;
/// 4. get b_hi :
///     if a_hi <> 0 , then b_hi = 2*a_hi -1;
///     if a.hi = 0, a_lo = 0, then b_hi = 2^128 -1;
///     if a_hi = 0, a_lo <> 0, then b_hi = 0;
/// 5. get c_lo :
///     if a_lo == 0 , c_lo =0;
///     if a_lo <> 0, c_lo = 2^128 - 2*a_lo
/// 6. get c_hi :
///     if a_hi == 0 , a_lo = 0 ,then c_hi = 0;
///     if a_hi == 0, a_lo <> 0 , then c_hi = 2^128 -1
///     if a_hi <> 0, then c_hi = 2^128 - 2*a_hi
/// 7. get d_hi : d_hi = not_is_zero * c_hi + (1-not_is_zero)*b_hi
/// 8. get d_lo : d_lo = not_is_zero * c_lo + (1-not_is_zero)*b_lo
/// 9. get final_result :
///     9.1 get operator :
///             if not_is_zero = 1, then operator = ||
///             if not_is_zero = 0, then operator = &
///     9.2 get final_result :
///             final_result = operand_1 operator d
///
/// ARITH 9 columns ,    
/// BITWISE lookup 4 * 5 columns,every lookup takes 5 columns;
/// four lookups:
///     BW0: originated at column 10, operand_1 hi & a hi; 5 columns
///     BW1: operand_1 lo & a lo; 5 columns
///     BW2: operand_1 hi operator d hi; 5 columns
///     BW3: operand_1 lo operator d lo; 5 columns
/// A_HI: a_hi  (algorithm step 1) ,1 column
/// A_LO: a_lo  (algorithm step 1) ,1 column
/// D_HI: d_hi (algorithm step 7) ,1 column
/// D_LO: d_lo  (algorithm step 8) ,1 column  
/// NZ: not_is_zero , 1 column
/// STATE0: operand_0 lookup , 8 columns
/// STATE1: operand_1 lookup , 8 columns
/// STATE2: final_result lookup, 8 columns
/// EXP: exp lookup , 6 columns
/// +---+---------+---------+-------------------------------+-------------+
/// |cnt| 8 col   | 8 col   | 8 col  |               8 col                |
/// +---+---------+---------+-------------------------------+-------------+
/// | 2 | ARITH     |  BW0 |  BW1  |  BW2  |   BW3          |             |
/// | 1 | STATE0  | STATE1  | STATE2 |                         EXP        |
/// | 0 |       DYNA_SELECTOR   | AUX   | A_HI | A_LO |D_HI |D_LO |NZ_INV |                         |
/// +---+---------+---------+-------------------------------+-------------+
pub struct SignextendGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for SignextendGadget<F>
{
    fn name(&self) -> &'static str {
        "SIGNEXTEND"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SIGNEXTEND
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
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        // [operand_0_hi,operand_0_lo,operand_1_hi,operand_1_lo,result_hi,result_lo]
        let mut stack_operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            // stack constraints
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        // get signextend operands
        let (
            signextend_a_hi,
            signextend_a_lo,
            signextend_d_hi,
            signextend_d_lo,
            sign_bit_is_zero_inv,
        ) = config.get_signextend_operands(meta);

        let (bitwise_lookups, sign_bit_is_zero) =
            config.get_signextend_bitwise_lookups(meta, sign_bit_is_zero_inv);
        constraints.extend(sign_bit_is_zero.get_constraints());

        // constrain arithmetic
        // arithmetic_operands[0] is 0
        // arithmetic_operands[1] is 31
        // arithmetic_operands[2] is stack_top0_hi
        // arithmetic_operands[3] is stack_top0_lo
        // arithmetic_tag is Sub
        let (arithmetic_constraints, byte_idx_is_gt_31) = config
            .get_signextend_sub_arith_constraints(
                meta,
                stack_operands[0].clone().to_vec(),
                BYTE_MAX_IDX.expr(),
            );
        constraints.extend(arithmetic_constraints);

        // exp constraints
        let exp_entry = config.get_exp_lookup(meta);
        let (base, index, pow) = extract_lookup_expression!(exp, exp_entry);
        constraints.extend([
            ("base hi".into(), base[0].clone()),
            ("base lo".into(), base[1].clone() - EXP_BASE.expr()), // sign_extend_by_byte
            (
                "index hi".into(),
                index[0].clone() - stack_operands[0][0].clone(),
            ),
            (
                "index lo".into(),
                index[1].clone() - stack_operands[0][1].clone(),
            ),
            (
                "pow[0] = a_hi".into(),
                pow[0].clone() * V_128.expr() - signextend_a_hi.clone(),
            ),
            (
                "pow[1] = a_lo".into(),
                pow[1].clone() * V_128.expr() - signextend_a_lo.clone(),
            ),
        ]);

        // bitwise lookup constraints
        constraints.extend(config.get_signextend_bitwise_constraints(
            bitwise_lookups,
            [signextend_a_hi, signextend_a_lo],
            stack_operands[1].clone(),
            [signextend_d_hi, signextend_d_lo],
            stack_operands[2].clone(),
            sign_bit_is_zero.expr(),
            byte_idx_is_gt_31.clone(),
        ));

        constraints.extend([(
            "opcode must be SIGNEXTEND".into(),
            opcode.clone() - OpcodeId::SIGNEXTEND.as_u8().expr(),
        )]);

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
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
            ("stack pop operand_1".into(), stack_lookup_1),
            ("stack push result".into(), stack_lookup_2),
            ("exp result".into(), exp_lookup),
            ("bitwise lookup 0".into(), bitwise_lookup_0),
            ("bitwise lookup 1".into(), bitwise_lookup_1),
            ("bitwise lookup 2".into(), bitwise_lookup_2),
            ("bitwise lookup 3".into(), bitwise_lookup_3),
            ("arithmetic lookup 0".into(), arithmetic_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // pop two elements from the top of the stack
        let (stack_pop_0, operand_0) = current_state.get_pop_stack_row_value(trace);
        let (stack_pop_1, operand_1) = current_state.get_pop_stack_row_value(trace);

        // get state push row
        let result = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, result);

        // get a = 128 * 256^operand_0
        let exp_base = U256::from(EXP_BASE);
        let exp_index = operand_0;
        let (calc_exp_power, exp_rows, exp_arith_mul_rows) =
            exp::Row::from_operands(exp_base, exp_index);
        let signextend_a: U256 = U256::from(V_128) * calc_exp_power;

        // Construct core_row_2,core_row_1,core_row_0  object
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        let mut core_row_0 = ExecutionState::SIGNEXTEND.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // insert state lookup to core_row_1
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(exp_base, exp_index, calc_exp_power);

        // get signextend related rows
        let (bitwise_rows, arithmetic_sub_rows) = get_and_insert_signextend_rows::<F>(
            [signextend_a, operand_1],
            [U256::from(BYTE_MAX_IDX), operand_0],
            &mut core_row_0,
            &mut core_row_1,
            &mut core_row_2,
        );

        // Construct witness  object
        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(arithmetic_sub_rows);
        arithmetic_rows.extend(exp_arith_mul_rows);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            exp: exp_rows,
            bitwise: bitwise_rows,
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(SignextendGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SIGNEXTEND, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
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
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        //witness.print_csv();
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_normal() {
        let stack_1 = Stack::from_slice(&[0x7F.into(), 0.into()]);
        let stack_top_1 = U256::from(0x7f);
        run(stack_1, stack_top_1);
    }

    #[test]
    fn test_normal2() {
        let stack_1 = Stack::from_slice(&[0.into(), 31.into()]);
        let stack_top_1 = U256::from(0);
        run(stack_1, stack_top_1);
    }

    #[test]
    fn test_extend_1() {
        let stack_0 = Stack::from_slice(&[0xFF.into(), 0.into()]);
        let stack_top_0 = U256::MAX;
        run(stack_0, stack_top_0);
    }

    #[test]
    fn test_b_gt_31() {
        let stack_2 = Stack::from_slice(&[0xFF.into(), 33.into()]);
        let stack_top_2 = U256::from(0xff);
        run(stack_2, stack_top_2);
    }

    #[test]
    fn test_b_gt_31_2() {
        let stack_2 = Stack::from_slice(&[0xFF.into(), U256::MAX]);
        let stack_top_2 = U256::from(0xff);
        run(stack_2, stack_top_2);
    }
}
