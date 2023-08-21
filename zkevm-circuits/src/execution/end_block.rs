use crate::execution::{Auxiliary, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{CurrentState, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

pub(crate) const NUM_ROW: usize = 1;

pub struct EndBlockGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndBlockGadget<F>
{
    fn name(&self) -> &'static str {
        "END_CALL"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_BLOCK
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let Auxiliary {
            state_stamp,
            log_stamp,
            ..
        } = config.get_auxiliary();
        let state_stamp_cur = meta.query_advice(state_stamp, Rotation::cur());
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let log_stamp_cur = meta.query_advice(log_stamp, Rotation::cur());
        let log_stamp_prev = meta.query_advice(log_stamp, Rotation(-1 * NUM_ROW as i32));
        // prev state should be stop or self, temporarily todo
        let prev_is_stop = config.execution_state_selector.selector(
            meta,
            ExecutionState::STOP as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        let prev_is_end_block = config.execution_state_selector.selector(
            meta,
            ExecutionState::END_BLOCK as usize,
            Rotation(-1 * NUM_ROW as i32),
        );

        vec![
            ("special next pc = 0".into(), pc_next),
            (
                "state stamp is kept in padding".into(),
                state_stamp_cur - state_stamp_prev,
            ),
            (
                "log stamp is kept in padding".into(),
                log_stamp_cur - log_stamp_prev,
            ),
            (
                "prev is stop or self".into(),
                prev_is_stop + prev_is_end_block - 1.expr(),
            ),
        ]
    }

    fn get_lookups(
        &self,
        _: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, _: &Trace, current_state: &mut CurrentState) -> Witness {
        let core_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EndBlockGadget {
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
        // prepare a state to generate witness
        let stack = Stack::new();
        let mut current_state = CurrentState::new();
        // prepare a trace
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
        let mut padding_end_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
