use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{CurrentState, Witness};
use eth_types::Field;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 1;

pub struct JumpdestGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for JumpdestGadget<F>
{
    fn name(&self) -> &'static str {
        "JUMPDEST"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::JUMPDEST
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
        let core_row_0 = ExecutionState::JUMPDEST.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_0],
            state: vec![],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(JumpdestGadget {
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
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::STOP,
            push_value: None,
        };
        current_state.copy_from_trace(&trace);
        let mut padding_begin_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_begin_row.vers_21 = Some(stack_pointer.into());
        let mut padding_end_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
