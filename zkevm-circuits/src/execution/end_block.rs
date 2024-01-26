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
        let delta = AuxiliaryOutcome::default();
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // 约束指令当前的stamp与state电路的stamp
        let Auxiliary {
            state_stamp,
            log_stamp,
            ..
        } = config.get_auxiliary();
        let state_stamp = meta.query_advice(state_stamp, Rotation::cur());
        let (state_circuit_tag, cnt) =
            extract_lookup_expression!(cnt, config.get_stamp_cnt_lookup(meta));
        let log_stamp = meta.query_advice(log_stamp, Rotation::cur());
        let (public_tag, _, [public_log_stamp_in_block, _, _, _]) =
            extract_lookup_expression!(public, config.get_public_lookup(meta));

        constraints.extend([
            ("special next pc = 0".into(), pc_next),
            (
                "last stamp in state circuit = current stamp + 1".into(),
                state_stamp + 1.expr() - cnt,
            ),
            (
                "last tag in state circuit = end padding".into(),
                state_circuit_tag - (Tag::EndPadding as u8).expr(),
            ),
        ]);
        // prev state should be end_tx.
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::END_TX], NUM_ROW, vec![]),
        ));

        // log stamp constraint
        constraints.push((
            "tag is BlockLogNum".into(),
            public_tag - (public::Tag::BlockLogNum as u8).expr(),
        ));

        constraints.push((
            "log stamp = log stamp in lookup".into(),
            log_stamp - public_log_stamp_in_block,
        ));
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stamp_cnt_lookup = query_expression(meta, |meta| config.get_stamp_cnt_lookup(meta));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta));
        vec![
            ("stamp_cnt".into(), stamp_cnt_lookup),
            ("public_log_stamp_lookup".into(), public_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_public_lookup(&current_state.get_public_tx_row(public::Tag::BlockLogNum));

        let state_circuit_end_padding = state::Row {
            tag: Some(Tag::EndPadding),
            stamp: Some((current_state.state_stamp + 1).into()),
            ..Default::default()
        };

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&state_circuit_end_padding]);

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
            ..WitnessExecHelper::new()
        };
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
        _witness.print_csv();
        prover.assert_satisfied_par();
    }
}
