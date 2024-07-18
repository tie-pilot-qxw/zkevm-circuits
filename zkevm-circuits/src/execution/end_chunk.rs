use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState, ExpressionOutcome,
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

/// end_chunk runs after the execution of a chunk, recording some end states and constraining with other circuits.
/// It records the number of rows used by the state circuit.
///
/// END_CHUNK Execution State layout is as follows.
/// P_BLOCK_NUM  (6 columns) means lookup tx num in block from core circuit to public circuit,
/// TAG is END_PADDING flag to identify ending.
/// CNT is the num of state row that has been used.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+--------------+
/// |cnt| 8 col | 8 col | 8 col |     8 col    |
/// +---+-------+-------+-------+--------------+
/// | 2 |       |                  |P_BLOCK_NUM|
/// | 1 |TAG|CNT|                              |
/// | 0 | DYNA_SELECTOR   | AUX                |
/// +---+-------+-------+-------+--------------+
pub struct EndChunkGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndChunkGadget<F>
{
    fn name(&self) -> &'static str {
        "END_CHUNK"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_CHUNK
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
        // get some status from core
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());

        let mut constraints = vec![];

        // next state, all core status would be 0
        let delta_core = CoreSinglePurposeOutcome {
            block_idx: ExpressionOutcome::To(0.expr()),
            tx_idx: ExpressionOutcome::To(0.expr()),
            tx_is_create: ExpressionOutcome::To(0.expr()),
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(0.expr()),
            code_addr: ExpressionOutcome::To(0.expr()),
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta_core));

        // get auxiliary constraints. All status must keep same with previous state.
        let delta = AuxiliaryOutcome::default();
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // prev state should be end_block.
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::END_BLOCK], NUM_ROW, vec![], None),
        ));

        // get current state stamp
        let state_stamp = meta.query_advice(config.get_auxiliary().state_stamp, Rotation::cur());

        // get state lookup and public lookup
        let (state_circuit_tag, cnt) =
            extract_lookup_expression!(cnt, config.get_stamp_cnt_lookup(meta));
        let (public_tag, _, [_, _, _, block_num_in_chunk]) =
            extract_lookup_expression!(public, config.get_public_lookup(meta, 0));

        // constraint tag
        constraints.push((
            "state tag is EndPadding".into(),
            state_circuit_tag - (Tag::EndPadding as u8).expr(),
        ));
        constraints.push((
            "tag is BlockNumber".into(),
            public_tag - (public::Tag::BlockNumber as u8).expr(),
        ));

        // state_stamp is the last one
        constraints.extend([(
            "last stamp in state circuit = cnt in lookup".into(),
            state_stamp - cnt,
        )]);

        // block_idx is the last one
        constraints.push((
            "last block idx in state = block number in lookup".into(),
            block_num_in_chunk - block_idx.clone(),
        ));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stamp_cnt_lookup = query_expression(meta, |meta| config.get_stamp_cnt_lookup(meta));
        let public_block_num_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stamp_cnt".into(), stamp_cnt_lookup),
            ("public_block_num_lookup".into(), public_block_num_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // row 0
        let core_row_0 = ExecutionState::END_CHUNK.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // row 1 records the number of rows used by the state circuit.
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_stamp_cnt_lookups(current_state.state_stamp.into());

        // row 2
        // get public lookup for block_number_in_chunk
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_public_lookup(
            0,
            &current_state.get_public_tx_row(public::Tag::BlockNumber, 0),
        );

        // state lookup
        let state_circuit_end_padding = state::Row {
            tag: Some(Tag::EndPadding),
            ..Default::default()
        };

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![state_circuit_end_padding],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EndChunkGadget {
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
            ExecutionState::END_BLOCK.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.block_idx = 0.into();
            row.tx_idx = 0.into();
            row
        };
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied();
    }
}
