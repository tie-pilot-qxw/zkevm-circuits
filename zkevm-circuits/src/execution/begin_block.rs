use eth_types::{Field, GethExecStep};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use crate::execution::{
    begin_tx_1, Auxiliary, ExecStateTransition, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::LookupEntry;
use crate::witness::{Witness, WitnessExecHelper};

use std::marker::PhantomData;
use std::vec;

const NUM_ROW: usize = 1;
pub struct BeginBlockGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginBlockGadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_BLOCK"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_BLOCK
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (0, begin_tx_1::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // pc = 0
        let mut constraints = vec![];
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        constraints.extend([("pc cur = 0".into(), pc_cur)]);
        // 因为begin_block为第一条辅助状态数据，所以所有的值都应该为0
        let Auxiliary {
            state_stamp,
            stack_pointer,
            log_stamp,
            ..
        } = config.get_auxiliary();
        constraints.extend([
            (
                "state_stamp = 0".into(),
                meta.query_advice(state_stamp, Rotation::cur()),
            ),
            (
                "stack_pointer = 0".into(),
                meta.query_advice(stack_pointer, Rotation::cur()),
            ),
            (
                "log_stamp = 0".into(),
                meta.query_advice(log_stamp, Rotation::cur()),
            ),
        ]);

        // 下一条执行指令应该为begin_tx
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::BEGIN_TX_1, begin_tx_1::NUM_ROW, None)],
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
        let core_row_0 = ExecutionState::BEGIN_BLOCK.into_exec_state_core_row(
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
    Box::new(BeginBlockGadget {
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
            let row = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
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
