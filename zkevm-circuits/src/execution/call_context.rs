use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::state::CallContextTag;
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = 1;

/// CallContextGadget deal OpCodeId:{CALLDATASIZE, CALLER, CALLVALUE}
/// STATE0 read value from call_context
/// STATE1 write value to stack
/// TAGSELECTOR 3 columns
/// +---+-------+-------+------------------+
/// |cnt| 8 col | 8 col |     16 col       |
/// +---+-------+-------+------------------+
/// | 1 | STATE1| STATE2|       TAGSELECTOR|
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+------------------+
pub struct CallContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CallContextGadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_CONTEXT
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let calldatasize_tag = meta.query_advice(config.vers[29], Rotation::prev());
        let caller_tag = meta.query_advice(config.vers[30], Rotation::prev());
        let callvalue_tag = meta.query_advice(config.vers[31], Rotation::prev());
        // create a simple selector representing:
        // - CALLDATASIZE,
        // - CALLER,
        // - CALLVALUE,
        let selector = SimpleSelector::new(&[calldatasize_tag, caller_tag, callvalue_tag]);

        let mut operands = vec![];

        let call_context_tag = selector.select(&[
            (CallContextTag::CallDataSize as u8).expr(),
            (CallContextTag::SenderAddr as u8).expr(),
            (CallContextTag::Value as u8).expr(),
        ]);

        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);

            if i == 0 {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    call_context_tag.clone(),
                    call_id.clone(),
                ));
            } else {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    1.expr(),
                    true,
                ));
            }

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let a = &operands[0];
        let b = &operands[1];

        constraints.extend(selector.get_constraints());

        // opcode constraints
        constraints.extend([(
            "opcode is correct".into(),
            opcode
                - selector.select(&[
                    OpcodeId::CALLDATASIZE.as_u8().expr(),
                    OpcodeId::CALLER.as_u8().expr(),
                    OpcodeId::CALLVALUE.as_u8().expr(),
                ]),
        )]);

        constraints.extend([
            (
                "pop value_hi = push value_hi".into(),
                a[0].clone() - b[0].clone(),
            ),
            (
                "pop value_lo = push value_lo".into(),
                a[1].clone() - b[1].clone(),
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
        vec![
            ("call_context pop a".into(), stack_lookup_0),
            ("stack push b".into(), stack_lookup_1),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, value) = current_state.get_call_context_read_row(&trace);

        let stack_push_0 = current_state.get_push_stack_row(trace, value);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        let tag = match trace.op {
            OpcodeId::CALLDATASIZE => 0,
            OpcodeId::CALLER => 1,
            OpcodeId::CALLVALUE => 2,
            _ => panic!("not CALLDATASIZE, CALLER or CALLVALUE"),
        };

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);
        // tag selector
        simple_selector_assign(
            [
                &mut core_row_1.vers_29,
                &mut core_row_1.vers_30,
                &mut core_row_1.vers_31,
            ],
            tag,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::CALL_CONTEXT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CallContextGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::HashMap;
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint_calldata_size() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut call_data = HashMap::new();
        call_data.insert(0_u64, vec![1_u8, 2_u8]);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            call_data,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::CALLDATASIZE, stack);
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

    #[test]
    fn assign_and_constraint_caller() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut sender = HashMap::new();
        sender.insert(0_u64, U256::max_value());
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            sender,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::CALLER, stack);
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

    #[test]
    fn assign_and_constraint_value() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut value = HashMap::new();
        value.insert(0, U256::zero());
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            value,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::CALLVALUE, stack);
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
