use crate::execution::{
    Auxiliary, AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;

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
        // prev state should be stop, or return_revert. temporarily todo
        let prev_is_stop = config.execution_state_selector.selector(
            meta,
            ExecutionState::STOP as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        let prev_is_return_revert = config.execution_state_selector.selector(
            meta,
            ExecutionState::RETURN_REVERT as usize,
            Rotation(-1 * NUM_ROW as i32),
        );
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let state_stamp = meta.query_advice(state_stamp, Rotation::cur());
        let delta = AuxiliaryDelta::default();
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let (state_circuit_tag, state_circuit_stamp, _, _, _, _, _, _) =
            extract_lookup_expression!(state, config.get_state_lookup(meta, 0)); // after state circuit has sorting, this may change todo
        constraints.extend([
            ("special next pc = 0".into(), pc_next),
            (
                "prev is stop or return_revert".into(),
                prev_is_stop + prev_is_return_revert - 1.expr(),
            ),
            (
                "last stamp in state circuit = current stamp - 1".into(),
                state_stamp - state_circuit_stamp - 1.expr(),
            ),
            (
                "last tag in state circuit = end padding".into(),
                state_circuit_tag - (state::Tag::EndPadding as u8).expr(),
            ),
        ]);
        // todo log stamp constraints
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let state_circuit_end_padding =
            query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        vec![(
            "state_circuit_end_padding".into(),
            state_circuit_end_padding,
        )]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let state_circuit_end_padding = state::Row {
            tag: Some(state::Tag::EndPadding),
            stamp: Some((current_state.state_stamp - 1).into()),
            value_hi: None,
            value_lo: None,
            call_id_contract_addr: None,
            pointer_hi: None,
            pointer_lo: None,
            is_write: None,
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
            core: vec![core_row_1, core_row_0],
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
            ..WitnessExecHelper::new()
        };
        // prepare a trace
        let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
        let padding_begin_row = |current_state| {
            ExecutionState::STOP.into_exec_state_core_row(
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
