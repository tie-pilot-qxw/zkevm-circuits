use crate::arithmetic_circuit::operation;

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
const B_INV_COL_IDX: usize = 31;

/// SdivSmod Execution State layout is as follows
/// where STATE means state table lookup,
/// ARITH means arithmetic table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// STATE0 is a_lo, a_hi
/// STATE1 is b_lo, b_hi
/// STATE2 is c_lo, c_hi
/// STATE3 is d_lo, d_hi
/// cnt == 2, vers_31 is b_inv
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH|      |       |    |b_inv(2)|
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct SdivSmodGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for SdivSmodGadget<F>
{
    fn name(&self) -> &'static str {
        "SDIV_SMOD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SDIV_SMOD
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

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));
        let mut arithmetic_operands = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                if i == 0 { 0 } else { -1 }.expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            arithmetic_operands.extend([value_hi, value_lo]);
        }
        let (tag, arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));
        // iterate over three operands (0..6), since we don't need constraint on the fourth
        constraints.extend((0..4).map(|i| {
            (
                format!("operand[{}] in arithmetic = in state lookup", i),
                arithmetic_operands[i].clone() - arithmetic_operands_full[i].clone(),
            )
        }));

        let b_inv = meta.query_advice(config.vers[B_INV_COL_IDX], Rotation(-2));

        let b = arithmetic_operands[2].clone() + arithmetic_operands[3].clone();
        let iszero_gadget = SimpleIsZero::new(&b, &b_inv, String::from("b"));

        // if divisor is zero, the result is 1
        let divisor_is_zero = iszero_gadget.expr();
        //d is dividend and c is mod
        constraints.extend([
            (
                // arithmetic_operands_full:
                //  - 0 is a_hi;
                //  - 1 is a_lo;
                //  - 2 is b_hi;
                //  - 3 is b_lo;
                //  - 4 is c_hi; -- quotient_hi
                //  - 5 is c_lo; -- quotient_lo
                //  - 6 is d_hi; -- remainder_hi
                //  - 7 is d_lo; -- remainder_lo
                // operand:
                //  - 0 is a_hi;
                //  - 1 is a_lo;
                //  - 2 is b_hi;
                //  - 3 is b_lo;
                //  - 4 is quotient_hi  (SDIV)
                //  - 5 is quotient_lo  (SDIV)
                //  - 4 is remainder_hi (SMOD)
                //  - 5 is remainder_lo (SMOD)

                // when arithmetic is SDIV, c_hi in lookup = in state
                format!(
                    "operand[{}] c_hi in state lookup = operand[{}] c_hi in arithmetic",
                    4, 4
                ),
                (opcode.clone() - OpcodeId::SMOD.as_u8().expr())
                    * (arithmetic_operands[4].clone() - arithmetic_operands_full[4].clone()),
            ),
            (
                // when arithmetic is SDIV, c_lo in lookup = in state
                format!(
                    "operand[{}] c_lo in state lookup = operand[{}] c_lo in arithmetic",
                    5, 5
                ),
                (opcode.clone() - OpcodeId::SMOD.as_u8().expr())
                    * (arithmetic_operands[5].clone() - arithmetic_operands_full[5].clone()),
            ),
            (
                // when arithmetic is SMOD, d_hi in lookup = in state
                format!(
                    "operand[{}] d_hi in arithmetic = operand[{}] d_hi in state lookup.when divisor is not zero. ",
                    4, 6
                ),
                (opcode.clone() - OpcodeId::SDIV.as_u8().expr())
                    * (arithmetic_operands[4].clone() - arithmetic_operands_full[6].clone())
                    * (1.expr() - divisor_is_zero.clone()),
            ),
            (
                // when arithmetic is SMOD, d_lo in lookup = in state
                format!(
                    "operand[{}] d_lo in arithmetic = operand[{}] d_lo in state lookup.when divisor is not zero.",
                    5, 7
                ),
                (opcode.clone() - OpcodeId::SDIV.as_u8().expr())
                    * (arithmetic_operands[5].clone() - arithmetic_operands_full[7].clone())
                *  (1.expr() - divisor_is_zero.clone()),
            ),
            // if b == 0, result_lo == 0
            (
                "if divisor is zero then state operand_hi must is zero.".to_string(),
                (opcode.clone() - OpcodeId::SDIV.as_u8().expr()) * divisor_is_zero.clone() *  arithmetic_operands[5].clone() ,
            ),
            // if b == 0, result_hi == 0
            (
                "if divisor is zero then state operand_lo must is zero.".to_string(),
                (opcode.clone() - OpcodeId::SDIV.as_u8().expr()) * divisor_is_zero.clone() * arithmetic_operands[4].clone() ,
            ),
        ]);

        constraints.extend([
            (
                "opcode".into(),
                (opcode.clone() - OpcodeId::SDIV.as_u8().expr())
                    * (opcode - OpcodeId::SMOD.as_u8().expr()),
            ),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::SdivSmod as u8).expr(),
            ),
        ]);

        //inv of operand1
        constraints.extend(iszero_gadget.get_constraints());

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
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_a, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_b, b) = current_state.get_pop_stack_row_value(&trace);

        let (arithmetic, result) = operation::sdiv_smod::gen_witness(vec![a, b]);

        let stack_push = match trace.op {
            OpcodeId::SDIV => {
                assert_eq!(result[1], current_state.stack_top.unwrap());
                current_state.get_push_stack_row(trace, result[1])
            }
            OpcodeId::SMOD => {
                assert_eq!(result[0], current_state.stack_top.unwrap());
                current_state.get_push_stack_row(trace, result[0])
            }
            _ => panic!("opcode is not SDIV or SMOD"),
        };

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic);

        // tips: It is not necessary to calculate the multiplicative inverse of operand_lo and operand_hi separately
        // when seeking the multiplicative inverse of a U256 number.
        // What we are doing here is calculating the multiplicative inverse of operand_lo + operand_hi,
        // which saves one cell.
        let b_hi = F::from_u128((b >> 128).as_u128());
        let b_lo = F::from_u128(b.low_u128());
        let b_inv =
            U256::from_little_endian((b_lo + b_hi).invert().unwrap_or(F::ZERO).to_repr().as_ref());

        //b_lo_inv
        assign_or_panic!(core_row_2[B_INV_COL_IDX], b_inv);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_push]);

        let core_row_0 = ExecutionState::SDIV_SMOD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_a, stack_pop_b, stack_push],
            arithmetic,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(SdivSmodGadget {
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
    #[test]
    fn assign_and_constraint_smod() {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SMOD, stack);
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
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }

    #[test]
    fn assign_and_constraint_sdiv() {
        let stack = Stack::from_slice(&[U256::from(10), U256::from(1000)]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(100.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SDIV, stack);
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
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
