use crate::execution::{
    Auxiliary, AuxiliaryOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::state::Tag;
use crate::witness::{public, state, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;

/// BeginBlock 在区块执行结束后运行，记录一些结束状态与其它电路进行约束。
/// 记录state电路的使用的行数、以及log,区块中的tx的数量
///
///
/// END_BLOCK Execution State layout is as follows.
/// P_LOG_NUM (6 columns) means lookup log_num from core circuit to public circuit,
/// P_TX_NUM  (6 columns) means lookup tx num in block from core circuit to public circuit,
/// TAG is END_PADDING flag to identify endding.
/// CNT is the num of state row that has been used.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+--------------+
/// |cnt| 8 col | 8 col | 8 col |     8 col    |
/// +---+-------+-------+-------+--------------+
/// | 2 |       |           |P_TX_NUM|P_LOG_NUM｜
/// | 1 |TAG|CNT|                              |
/// | 0 | DYNA_SELECTOR   | AUX                |
pub struct EndBlockGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndBlockGadget<F>
{
    fn name(&self) -> &'static str {
        "END_BLOCK"
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());

        // 对辅助列进行约束，如stack_pointer、stamp等；
        let delta = AuxiliaryOutcome::default();
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // 约束指令当前的stamp与state电路的stamp
        let Auxiliary {
            state_stamp,
            log_stamp,
            ..
        } = config.get_auxiliary();
        // 获取当前stamp值，与core电路中记录的state状态进行约束
        let state_stamp = meta.query_advice(state_stamp, Rotation::cur());
        let (state_circuit_tag, cnt) =
            extract_lookup_expression!(cnt, config.get_stamp_cnt_lookup(meta));
        // 获取当前tx、log值，与core电路中记录的public状态进行约束
        let last_log_stamp = meta.query_advice(log_stamp, Rotation::cur());
        let (public_tag, public_block_idx, [public_tx_num, public_log_num, _, _]) =
            extract_lookup_expression!(public, config.get_public_lookup(meta, 0));

        constraints.extend([
            ("special next pc = 0".into(), pc_next),
            (
                "last stamp in state circuit = cnt in lookup".into(),
                state_stamp - cnt,
            ),
            (
                "last tag in state circuit = end padding".into(),
                state_circuit_tag - (Tag::EndPadding as u8).expr(),
            ),
        ]);
        // prev state should be end_tx.
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::END_TX], NUM_ROW, vec![], None),
        ));

        // tag constraint
        constraints.push((
            "tag is BlockTxLogNum".into(),
            public_tag - (public::Tag::BlockTxLogNum as u8).expr(),
        ));

        // block_idx constraint
        constraints.push((
            "last block idx in state = block idx in lookup".into(),
            public_block_idx - block_idx.clone(),
        ));

        constraints.push((
            "last log stamp in state = log num in lookup".into(),
            last_log_stamp - public_log_num,
        ));

        constraints.push((
            "last tx num in state = tx num in lookup".into(),
            tx_idx - public_tx_num,
        ));
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // 从core电路中读取state使用的行和public内容，分别与state电路和public电路进行lookup
        let stamp_cnt_lookup = query_expression(meta, |meta| config.get_stamp_cnt_lookup(meta));
        let public_tx_log_num_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stamp_cnt".into(), stamp_cnt_lookup),
            ("public_tx_log_num_lookup".into(), public_tx_log_num_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // core电路中记录区块中tx、log的数量，写入core_row_2行
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_public_lookup(
            0,
            &current_state.get_public_tx_row(public::Tag::BlockTxLogNum, 0),
        );

        let state_circuit_end_padding = state::Row {
            tag: Some(Tag::EndPadding),
            ..Default::default()
        };

        // 记录总共使用的状态state状态行数
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_stamp_cnt_lookups(current_state.state_stamp.into());

        // core电路写入 执行标识
        let core_row_0 = ExecutionState::END_BLOCK.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![state_circuit_end_padding],
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
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let mut current_state = WitnessExecHelper {
            state_stamp: 1,
            log_stamp: 1,
            block_idx: 1,
            tx_idx: 1,
            ..WitnessExecHelper::new()
        };
        current_state.log_num_in_block.insert(1, 1);
        current_state.tx_num_in_block.insert(1, 1);
        current_state.block_num_in_chunk = 1;

        // prepare a trace
        let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
        let padding_begin_row = |current_state| {
            ExecutionState::END_TX.into_exec_state_core_row(
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
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
