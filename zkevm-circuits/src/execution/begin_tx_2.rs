use crate::execution::{
    Auxiliary, AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{arithmetic, copy, CurrentState};
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

pub(super) const NUM_ROW: usize = 3;

pub struct BeginTx2Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// BeginTx2 Execution State layout is as follows
/// where STATE means state table lookup for writing call context,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 |        |      |       |          |
/// | 1 | STATE | STATE | STATE | STATE    |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginTx2Gadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_TX_2"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_TX_2
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
        let delta = AuxiliaryDelta {
            state_stamp: 4.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let delta = Default::default();
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
        let prev_is_begin_tx_1 = config.execution_state_selector.selector(
            meta,
            ExecutionState::BEGIN_TX_1 as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        constraints.extend([(
            "prev state is BEGIN_TX_1".into(),
            prev_is_begin_tx_1 - 1.expr(),
        )]);
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        // todo: lookup from public table
        let call_id = current_state.call_id;
        let value = *current_state.value.get(&call_id).unwrap();
        let sender = *current_state.sender.get(&call_id).unwrap();
        let write_value_row = current_state.get_write_call_context_row(
            Some((value >> 128).as_u128().into()),
            Some(value.low_u128().into()),
            state::CallContextTag::Value,
        );
        let write_sender_row = current_state.get_write_call_context_row(
            Some((sender >> 128).as_u128().into()),
            Some(sender.low_u128().into()),
            state::CallContextTag::SenderAddr,
        );
        let write_parent_pc_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            state::CallContextTag::ParentProgramCounter,
        );
        let write_parent_stack_pointer_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            state::CallContextTag::ParentStackPointer,
        );
        let mut core_row_2 = current_state.get_core_row_without_versatile(2);

        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([
            &write_value_row,
            &write_sender_row,
            &write_parent_pc_row,
            &write_parent_stack_pointer_row,
        ]);
        let core_row_0 = ExecutionState::BEGIN_TX_2.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![
                write_value_row,
                write_sender_row,
                write_parent_pc_row,
                write_parent_stack_pointer_row,
            ],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginTx2Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_witness_and_prover,
    };
    use std::collections::HashMap;
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let stack_pointer = stack.0.len();
        let call_id = 1;
        let value = HashMap::from([(call_id, 0xaaaaaa.into())]);
        let sender = HashMap::from([(call_id, 0xfffffff.into())]);
        let mut current_state = CurrentState {
            stack,
            call_id,
            value,
            sender,
            ..CurrentState::new()
        };
        // prepare a trace
        let trace = Trace {
            pc: 0,
            op: OpcodeId::PUSH1,
            stack_top: None,
        };
        current_state.copy_from_trace(&trace);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            ExecutionState::END_PADDING.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        // padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
