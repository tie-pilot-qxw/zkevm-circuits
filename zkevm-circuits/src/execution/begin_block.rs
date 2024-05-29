use crate::execution::{
    begin_tx_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::LookupEntry;
use crate::util::ExpressionOutcome;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};

use std::marker::PhantomData;
use std::vec;

const NUM_ROW: usize = 1;
/// BeginBlock 在区块开始执行前运行，作为一个Flag电路，标识接下来将执行一个新的区块。
/// 因为为Flag电路，所以witness不用填入其它状态，仅使用一行标识gadget 类型；
/// 同时约束所有的状态为初始值，因为区块刚开始执行。
///
///
/// BEGIN_BLOCK Execution State layout is as follows.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 0 | DYNA_SELECTOR   | AUX            |
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
        // let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        // constraints.extend([("pc cur = 0".into(), pc_cur)]);

        // All Auxiliary status needs to be reset to 0
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::To(0.expr()),
            stack_pointer: ExpressionOutcome::To(0.expr()),
            log_stamp: ExpressionOutcome::To(0.expr()),
            gas_left: ExpressionOutcome::To(0.expr()),
            refund: ExpressionOutcome::To(0.expr()),
            memory_chunk: ExpressionOutcome::To(0.expr()),
            read_only: ExpressionOutcome::To(0.expr()),
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, 0, delta));

        // reset pc, tx_idx, call_id, code_addr to 0
        let delta_core = CoreSinglePurposeOutcome {
            block_idx: ExpressionOutcome::To(1.expr()),
            tx_idx: ExpressionOutcome::To(0.expr()),
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(0.expr()),
            code_addr: ExpressionOutcome::To(0.expr()),
        };
        constraints.append(&mut config.get_cur_single_purpose_constraints(meta, 0, delta_core));

        // 下一条执行指令应该为begin_tx
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::BEGIN_TX_1, begin_tx_1::NUM_ROW, None)],
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
        // core电路写入 执行标识
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
        current_state.block_idx = 1;

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
