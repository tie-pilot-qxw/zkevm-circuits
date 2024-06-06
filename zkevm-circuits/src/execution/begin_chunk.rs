use crate::execution::{
    begin_block, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::LookupEntry;
use crate::util::ExpressionOutcome;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};

use std::marker::PhantomData;

pub const NUM_ROW: usize = 1;

/// BEGIN_CHUNK Execution State layout is as follows.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct BeginChunkGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginChunkGadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_CHUNK"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_CHUNK
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (1, begin_block::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // All Auxiliary status needs to be set to 0
        let delta = AuxiliaryOutcome {
            stack_pointer: ExpressionOutcome::To(0.expr()),
            log_stamp: ExpressionOutcome::To(0.expr()),
            gas_left: ExpressionOutcome::To(0.expr()),
            refund: ExpressionOutcome::To(0.expr()),
            memory_chunk: ExpressionOutcome::To(0.expr()),
            read_only: ExpressionOutcome::To(0.expr()),
            state_stamp: ExpressionOutcome::To(0.expr()),
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, 0, delta));

        // all core status needs to be set to 0
        let delta_core = CoreSinglePurposeOutcome {
            block_idx: ExpressionOutcome::To(0.expr()),
            tx_idx: ExpressionOutcome::To(0.expr()),
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(0.expr()),
            code_addr: ExpressionOutcome::To(0.expr()),
        };
        constraints.append(&mut config.get_cur_single_purpose_constraints(meta, 0, delta_core));

        // next excution state must be BEGIN_BLOCK
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::BEGIN_BLOCK, begin_block::NUM_ROW, None)],
                None,
            ),
        ));
        constraints
    }

    fn get_lookups(
        &self,
        _config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let core_row_0 = ExecutionState::BEGIN_CHUNK.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_0],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginChunkGadget {
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
        let mut current_state = WitnessExecHelper::new();

        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, Stack::new());
        let padding_begin_row = |current_state| {
            let row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };

        let padding_end_row = |current_state| {
            let row = ExecutionState::BEGIN_BLOCK.into_exec_state_core_row(
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
        prover.assert_satisfied_par();
    }
}
