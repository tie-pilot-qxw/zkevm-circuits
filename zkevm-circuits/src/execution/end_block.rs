use crate::execution::{
    begin_block, end_chunk, AuxiliaryOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;

const END_BLOCK_NEXT_IS_BEGIN_BLOCK: usize = 0;
const END_BLOCK_NEXT_IS_END_CHUNK: usize = 1;
const BLOCK_NUM_DIFF_INV_COL_OFFSET: usize = 2;

/// EndBlock runs after the execution of a block, recording some end states and constraining with other circuits.
/// It records the number of logs and transactions in the block.
///
/// END_BLOCK Execution State layout is as follows.
/// P_TX_LOG_NUM (6 columns) means lookup tx_num and log_num in current block from core circuit to public circuit,
/// P_BLOCK_NUM｜  (6 columns) means lookup block_number_in_chunk from core circuit to public circuit,
/// TAG1 is END_BLOCK_NEXT_IS_BEGIN_BLOCK, means that next state is begin_block.
/// TAG2 is END_BLOCK_NEXT_IS_END_CHUNK, means that next state is end_chunk.
/// B_INV is the (block_num_in_chunk - block_idx) inverse.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+--------------+
/// |cnt| 8 col | 8 col | 8 col |     8 col    |
/// +---+-------+-------+-------+--------------+
/// | 2 |       |     |P_TX_LOG_NUM|P_BLOCK_NUM|
/// | 1 |TAG1|TAG2|B_INV|                      |
/// | 0 | DYNA_SELECTOR   | AUX                |
/// +---+-------+-------+-------+--------------+
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
        // get block_idx and tx_idx from core
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());

        // constraints auxiliary, all status keep previous state
        let delta = AuxiliaryOutcome::default();
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // get the public lookup of BlockTxLogNumAndDifficulty and BlockNumber
        let last_log_stamp = meta.query_advice(config.get_auxiliary().log_stamp, Rotation::cur());
        let tx_log_num_entry = config.get_public_lookup(meta, 0);
        let block_num_entry = config.get_public_lookup(meta, 1);
        let (_, _, [_, _, _, block_num_in_chunk]) =
            extract_lookup_expression!(public, block_num_entry.clone());

        // constraint tx_idx = tx_num in current block
        // And constraint log_stamp = log_num in current block
        constraints.extend(config.get_public_constraints(
            meta,
            tx_log_num_entry,
            (public::Tag::BlockTxLogNumAndDifficulty as u8).expr(),
            Some(block_idx.clone()),
            [Some(tx_idx), Some(last_log_stamp), None, None],
        ));

        // only need to constrain the public tag
        constraints.extend(config.get_public_constraints(
            meta,
            block_num_entry,
            (public::Tag::BlockNumber as u8).expr(),
            None,
            [None, None, None, None],
        ));

        // get the next state tag
        let next_is_begin_block = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + END_BLOCK_NEXT_IS_BEGIN_BLOCK],
            Rotation::prev(),
        );
        let next_is_end_chunk = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + END_BLOCK_NEXT_IS_END_CHUNK],
            Rotation::prev(),
        );

        // get the (block_num_in_chunk - block_idx) inverse
        let block_idx_diff_inv = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + BLOCK_NUM_DIFF_INV_COL_OFFSET],
            Rotation::prev(),
        );

        // constraints block_idx_diff_inv and get signal is_zero
        let is_zero = SimpleIsZero::new(
            &(block_num_in_chunk.clone() - block_idx.clone()),
            &block_idx_diff_inv,
            String::from("block_id_diff"),
        );
        constraints.extend(is_zero.get_constraints());

        // constraints next state
        constraints.append(&mut config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::END_TX, ExecutionState::BEGIN_BLOCK],
                NUM_ROW,
                vec![
                    (
                        ExecutionState::BEGIN_BLOCK,
                        begin_block::NUM_ROW,
                        Some(next_is_begin_block),
                    ),
                    (
                        ExecutionState::END_CHUNK,
                        end_chunk::NUM_ROW,
                        Some(next_is_end_chunk),
                    ),
                ],
                Some(vec![1.expr() - is_zero.expr(), is_zero.expr()]),
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
        let public_block_number_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 1));
        vec![
            ("public_tx_log_num_lookup".into(), public_tx_log_num_lookup),
            (
                "public_block_number_lookup".into(),
                public_block_number_lookup,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // row 0
        let core_row_0 = ExecutionState::END_BLOCK.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        let offset = if current_state.block_num_in_chunk == current_state.block_idx {
            END_BLOCK_NEXT_IS_END_CHUNK
        } else {
            END_BLOCK_NEXT_IS_BEGIN_BLOCK
        };
        assign_or_panic!(
            core_row_1[NUM_STATE_HI_COL + NUM_STATE_LO_COL + offset],
            U256::one()
        );

        let block_num_diff = (current_state.block_num_in_chunk - current_state.block_idx) as u64;
        let block_num_diff_inv = U256::from_little_endian(
            F::from(block_num_diff)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        assign_or_panic!(
            core_row_1[NUM_STATE_HI_COL + NUM_STATE_LO_COL + BLOCK_NUM_DIFF_INV_COL_OFFSET],
            block_num_diff_inv
        );

        // row 2
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);

        // get the public lookup of BlockTxLogNumAndDifficulty and BlockNumber(for the block_number_in_chunk)
        core_row_2.insert_public_lookup(
            0,
            &current_state.get_public_tx_row(public::Tag::BlockTxLogNumAndDifficulty, 0),
        );
        core_row_2.insert_public_lookup(
            1,
            &current_state.get_public_tx_row(public::Tag::BlockNumber, 1),
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
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
            ExecutionState::END_CHUNK.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied();
    }
}
