use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::default;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
pub struct DivModGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for DivModGadget<F>
{
    fn name(&self) -> &'static str {
        "DIV_MOD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::DIV_MOD
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
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
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
        //d is divisor and c is mod
        constraints.extend([
            (
                format!(
                    "operand[{}] d_hi in state lookup = operand[{}] d_hi in arithmetic",
                    4, 4
                ),
                (opcode.clone() - OpcodeId::MOD.as_u8().expr())
                    * (arithmetic_operands[4].clone() - arithmetic_operands_full[4].clone()),
            ),
            (
                format!(
                    "operand[{}] d_lo in state lookup = operand[{}] d_lo in arithmetic",
                    5, 5
                ),
                (opcode.clone() - OpcodeId::MOD.as_u8().expr())
                    * (arithmetic_operands[5].clone() - arithmetic_operands_full[5].clone()),
            ),
            (
                format!(
                    "operand[{}] c_hi in arithmetic = operand[{}] c_hi in state lookup ",
                    4, 6
                ),
                (opcode.clone() - OpcodeId::DIV.as_u8().expr())
                    * (arithmetic_operands[4].clone() - arithmetic_operands_full[6].clone()),
            ),
            (
                format!(
                    "operand[{}] c_lo in arithmetic = operand[{}] c_lo in state lookup ",
                    5, 7
                ),
                (opcode.clone() - OpcodeId::DIV.as_u8().expr())
                    * (arithmetic_operands[5].clone() - arithmetic_operands_full[7].clone()),
            ),
        ]);
        constraints.extend([
            (
                "opcode".into(),
                (opcode.clone() - OpcodeId::DIV.as_u8().expr())
                    * (opcode - OpcodeId::MOD.as_u8().expr()),
            ),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::DivMod as u8).expr(),
            ),
        ]);
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

        let (arithmetic, result) = operation::div_mod::gen_witness(vec![a, b]);

        let stack_push = if trace.op == OpcodeId::DIV {
            assert_eq!(result[1], current_state.stack_top.unwrap());
            current_state.get_push_stack_row(trace, result[1])
        } else if trace.op == OpcodeId::MOD {
            assert_eq!(result[0], current_state.stack_top.unwrap());
            current_state.get_push_stack_row(trace, result[0])
        } else {
            panic!("opcode is not DIV or MOD");
        };

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_push]);

        let core_row_0 = ExecutionState::DIV_MOD.into_exec_state_core_row(
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
    Box::new(DivModGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use gadgets::util::split_u256_hi_lo;
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[u128::MAX.into(), U256::MAX]);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some((U256::one() << 128) + U256::one()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::DIV, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
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
