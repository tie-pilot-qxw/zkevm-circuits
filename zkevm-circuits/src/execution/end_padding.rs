use crate::execution::{
    Auxiliary, AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::LookupEntry;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 1;

pub struct EndPaddingGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndPaddingGadget<F>
{
    fn name(&self) -> &'static str {
        "END_PADDING"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_PADDING
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
        // prev state should be end_block or self
        let prev_is_end_block = config.execution_state_selector.selector(
            meta,
            ExecutionState::END_BLOCK as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        let prev_is_end_padding = config.execution_state_selector.selector(
            meta,
            ExecutionState::END_PADDING as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        let delta = AuxiliaryDelta::default();
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        constraints.extend([
            ("special next pc = 0".into(), pc_next),
            (
                "prev is end_block or self".into(),
                prev_is_end_block + prev_is_end_padding - 1.expr(),
            ),
        ]);
        constraints
    }

    fn get_lookups(
        &self,
        _: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let core_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            trace,
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
    Box::new(EndPaddingGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let mut current_state = WitnessExecHelper::new();
        // prepare a trace
        let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
        let padding_begin_row = |current_state| {
            ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let padding_end_row = |current_state| {
            ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
