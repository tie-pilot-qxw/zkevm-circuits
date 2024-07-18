use crate::execution::{
    begin_tx_1, end_block, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub const NUM_ROW: usize = 3;
const BLOCK_IDX_DELTA: i32 = 1;
const NEXT_STATE_IS_END_BLOCK: usize = 0;
const NEXT_STATE_IS_BEGIN_TX: usize = 1;
const TX_NUM_DIFF: usize = 2;

/// BEGIN_BLOCK Execution State layout is as follows.
/// DYNA_SELECTOR is dynamic selector of the state,
/// P_TX_LOG_NUM (6 columns) means lookup tx_num and log_num in current block from core circuit to public circuit,
/// TAG1 is NEXT_STATE_IS_END_BLOCK, means that next state is end_block.
/// TAG2 is NEXT_STATE_IS_BEGIN_TX, means that next state is begin_tx.
/// T_INV is the tx_num inverse.
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 |       |     |P_TX_LOG_NUM|       |
/// | 1 |TAG1|TAG2|T_INV|       |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
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
        (1, begin_tx_1::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // All Auxiliary status needs to be reset to 0, except for state_stamp
        let delta = AuxiliaryOutcome {
            stack_pointer: ExpressionOutcome::To(0.expr()),
            log_stamp: ExpressionOutcome::To(0.expr()),
            gas_left: ExpressionOutcome::To(0.expr()),
            refund: ExpressionOutcome::To(0.expr()),
            memory_chunk: ExpressionOutcome::To(0.expr()),
            read_only: ExpressionOutcome::To(0.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // reset pc, tx_idx, call_id, code_addr to 0, block_idx add 1
        let delta_core = CoreSinglePurposeOutcome {
            block_idx: ExpressionOutcome::Delta(BLOCK_IDX_DELTA.expr()),
            tx_idx: ExpressionOutcome::To(0.expr()),
            tx_is_create: ExpressionOutcome::To(0.expr()),
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(0.expr()),
            code_addr: ExpressionOutcome::To(0.expr()),
        };
        constraints
            .append(&mut config.get_cur_single_purpose_constraints(meta, NUM_ROW, delta_core));

        // constraints for BlockTxLogNumAndDifficulty lookup
        let tx_log_num_entry = config.get_public_lookup(meta, 0);
        let (_, _, [tx_num, _, _, _]) =
            extract_lookup_expression!(public, tx_log_num_entry.clone());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        constraints.extend(config.get_public_constraints(
            meta,
            tx_log_num_entry,
            (public::Tag::BlockTxLogNumAndDifficulty as u8).expr(),
            Some(block_idx.clone()),
            [None, None, None, None],
        ));

        // get the next state tag
        let next_is_end_block = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NEXT_STATE_IS_END_BLOCK],
            Rotation::prev(),
        );
        let next_is_begin_tx = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NEXT_STATE_IS_BEGIN_TX],
            Rotation::prev(),
        );

        // get the tx_num_inv
        let tx_num_inv = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + TX_NUM_DIFF],
            Rotation::prev(),
        );

        // constraints tx_num_inv and tx_num
        let tx_num_is_zero =
            SimpleIsZero::new(&tx_num.clone(), &tx_num_inv.clone(), String::from("tx_num"));
        constraints.extend(tx_num_is_zero.get_constraints());

        // constraints next state is either begin_tx or end_block
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![
                    (
                        ExecutionState::BEGIN_TX_1,
                        begin_tx_1::NUM_ROW,
                        Some(next_is_begin_tx),
                    ),
                    (
                        ExecutionState::END_BLOCK,
                        end_block::NUM_ROW,
                        Some(next_is_end_block),
                    ),
                ],
                Some(vec![
                    1.expr() - tx_num_is_zero.expr(),
                    tx_num_is_zero.expr(),
                ]),
            ),
        ));
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let public_tx_log_num_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![("public_tx_log_num_lookup".into(), public_tx_log_num_lookup)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // core电路写入 执行标识
        let core_row_0 = ExecutionState::BEGIN_BLOCK.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        let tx_num = current_state
            .tx_num_in_block
            .get(&current_state.block_idx)
            .unwrap()
            .clone();
        let tx_num_diff = U256::from_little_endian(
            F::from(tx_num as u64)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        let next_is_end_block = if tx_num == 0 { 1 } else { 0 }.into();
        assign_or_panic!(
            core_row_1[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NEXT_STATE_IS_END_BLOCK],
            next_is_end_block
        );
        assign_or_panic!(
            core_row_1[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NEXT_STATE_IS_BEGIN_TX],
            U256::one() - next_is_end_block
        );
        assign_or_panic!(
            core_row_1[NUM_STATE_HI_COL + NUM_STATE_LO_COL + TX_NUM_DIFF],
            tx_num_diff
        );

        // row 2
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        // get the public lookup of BlockTxLogNum
        core_row_2.insert_public_lookup(
            0,
            &current_state.get_public_tx_row(public::Tag::BlockTxLogNumAndDifficulty, 0),
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
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
        current_state.block_idx = 2;
        current_state
            .tx_num_in_block
            .insert(current_state.block_idx, 99);
        current_state
            .log_num_in_block
            .insert(current_state.block_idx, 1);

        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, Stack::new());
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.block_idx = 1.into();
            row
        };

        let padding_end_row = |current_state_end| {
            let mut row = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
                &trace,
                current_state_end,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.block_idx = 2.into();
            row
        };

        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
