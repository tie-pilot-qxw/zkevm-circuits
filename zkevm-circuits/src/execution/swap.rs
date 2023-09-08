// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{CurrentState, Witness};
use eth_types::Field;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 2;

/// Dup Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE | STATE | STATE |  STATE   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct SwapGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for SwapGadget<F>
{
    fn name(&self) -> &'static str {
        "SWAP"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SWAP
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
        vec![]
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert!(current_state.opcode.is_swap());
        let (stack_read_1, value_1) = current_state
            .get_peek_stack_row_value(current_state.opcode.postfix().unwrap() as usize + 1);
        let (stack_read_2, value_2) = current_state.get_peek_stack_row_value(1);
        let stack_write_1 = current_state.get_overwrite_stack_row(1, value_1);
        let stack_write_2 = current_state.get_overwrite_stack_row(
            current_state.opcode.postfix().unwrap() as usize + 1,
            value_2,
        );

        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([
            &stack_read_1,
            &stack_read_2,
            &stack_write_1,
            &stack_write_2,
        ]);

        let core_row_0 = ExecutionState::SWAP.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_read_1, stack_read_2, stack_write_1, stack_write_2],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(SwapGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0.into(), 10.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::SWAP2,
            stack_top: Some(0xff.into()),
        };
        current_state.copy_from_trace(&trace);
        let mut padding_begin_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_begin_row.vers_21 = Some(stack_pointer.into());
        let mut padding_end_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        assert_eq!(
            Stack::from_slice(&[1.into(), 10.into(), 0.into()]),
            current_state.stack,
            "stack is not swapped!"
        );
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
