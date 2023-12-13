use crate::execution::{
    Auxiliary, AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, copy, WitnessExecHelper};
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;

pub struct BeginTx1Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// BeginTx1 Execution State layout is as follows
/// where STATE means state table lookup for writing call context,
/// COPY means copy table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY   |      |       |          |
/// | 1 | STATE | STATE | STATE | STATE    |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginTx1Gadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_TX_1"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_TX_1
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, super::begin_tx_2::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let copy = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, _, copy_size, _) = extract_lookup_expression!(copy, copy);
        let delta = AuxiliaryDelta {
            state_stamp: 4.expr() + copy_size,
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let delta = CoreSinglePurposeOutcome {
            tx_idx: ExpressionOutcome::Delta(1.expr()),
            call_id: ExpressionOutcome::To(state_stamp_prev + 1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
        let next_is_begin_tx_2 = config.execution_state_selector.selector(
            meta,
            ExecutionState::BEGIN_TX_2 as usize,
            Rotation(super::begin_tx_2::NUM_ROW as i32),
        );
        let next_begin_tx_2_cnt_is_zero = config
            .cnt_is_zero
            .expr_at(meta, Rotation(super::begin_tx_2::NUM_ROW as i32));
        constraints.extend([(
            "next state is BEGIN_TX_2".into(),
            next_begin_tx_2_cnt_is_zero * next_is_begin_tx_2 - 1.expr(),
        )]);
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let tx_idx = current_state.tx_idx + 1;
        let call_id = current_state.state_stamp + 1;
        // todo: lookup addr from public table
        let addr = current_state.code_addr;
        let write_addr_row = current_state.get_write_call_context_row(
            Some((addr >> 128).as_u128().into()),
            Some(addr.low_u128().into()),
            state::CallContextTag::StorageContractAddr,
        );
        let calldata_size = current_state
            .call_data
            .get(&call_id)
            .map(|v| v.len())
            .unwrap_or_default();
        let write_calldata_size_row = current_state.get_write_call_context_row(
            None,
            Some(calldata_size.into()),
            state::CallContextTag::CallDataSize,
        );
        let write_parent_call_id_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            state::CallContextTag::ParentCallId,
        );
        let write_parent_code_addr_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            state::CallContextTag::ParentCodeContractAddr,
        );
        let (copy_rows, state_rows_from_copy) = if calldata_size > 0 {
            current_state.get_load_calldata_copy_rows::<F>()
        } else {
            (vec![], vec![])
        };
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        if calldata_size > 0 {
            core_row_2.insert_copy_lookup(copy_rows.first().unwrap(), None);
        } else {
            // no actually copy, but we need to insert same format placeholders to satisfy constraint
            core_row_2.insert_copy_lookup(
                &copy::Row {
                    byte: 0.into(), //not used
                    src_type: copy::Tag::PublicCalldata,
                    src_id: tx_idx.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Calldata,
                    dst_id: call_id.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: current_state.state_stamp.into(),
                    cnt: 0.into(), //not used
                    len: calldata_size.into(),
                    acc: 0.into(),
                },
                None,
            );
        }

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([
            &write_addr_row,
            &write_calldata_size_row,
            &write_parent_call_id_row,
            &write_parent_code_addr_row,
        ]);
        let core_row_0 = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let mut state = vec![
            write_addr_row,
            write_calldata_size_row,
            write_parent_call_id_row,
            write_parent_code_addr_row,
        ];
        state.extend(state_rows_from_copy);
        // update current_state for tx_idx and call_id
        current_state.tx_idx = tx_idx;
        current_state.call_id = call_id;
        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginTx1Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::HashMap;
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let stack_pointer = stack.0.len();
        let call_id = 1;
        let call_data = HashMap::from([(call_id, vec![0xa, 0xb])]);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_id,
            call_data,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            ExecutionState::BEGIN_TX_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        // padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row); //todo change begin row too
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
