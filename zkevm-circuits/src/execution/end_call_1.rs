// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    end_call_2, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;

pub struct EndCall1Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Stop Execution State layout is as follows
/// where STATE1 means state table lookup (call_context write returndata_call_id),
/// STATE2 means state table lookup (call_context write returndata_size),
/// RETURNDATASIZE means the updated returndata_size used by the next execution state (END_CALL),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+---------+
/// |cnt| 8 col | 8 col | 8 col |  8col   |
/// +---+-------+-------+-------+---------+
/// | 1 | STATE1| STATE2|                 |
/// | 0 | DYNA_SELECTOR   | AUX     |RETURNDATASIZE(1) |
/// +---+-------+-------+-------+---------+
///
/// Note: here we constraint RETURNDATASIZE == 0.expr()
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndCall1Gadget<F>
{
    fn name(&self) -> &'static str {
        "END_CALL_1"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_CALL_1
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, NUM_ROW) // end unusable rows is super::end_call::NUM_ROW
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let returndata_size_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        //constraint returndata_size == 0
        constraints.extend([(
            "returndata_size_for_next == 0".into(),
            returndata_size_for_next,
        )]);

        // append state_lookup constraints
        let mut operands = vec![];
        for i in 0..2 {
            let state_entry = config.get_state_lookup(meta, i);

            constraints.append(
                &mut config.get_call_context_constraints(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    if i == 0 {
                        state::CallContextTag::ReturnDataCallId as u8
                    } else {
                        state::CallContextTag::ReturnDataSize as u8
                    }
                    .expr(),
                    if i == 0 { 0.expr() } else { call_id.clone() }, // when CallContextTag is ReturnDataCallId, the call_id is 0.
                ),
            );

            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state lookup's values
        constraints.extend([
            ("returndata_call_id hi == 0".into(), operands[0][0].clone()),
            (
                "returndata_call_id lo == call_id".into(),
                operands[0][1].clone() - call_id.clone(),
            ),
            ("returndata_size hi == 0".into(), operands[1][0].clone()),
            ("returndata_size lo == 0".into(), operands[1][1].clone()),
        ]);

        // append core single purpose constraints
        let delta = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // next execution state should be END_CALL
        // 前一个状态还需要对应error 例如 error_invalid_jump
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::STOP],
                NUM_ROW,
                vec![(ExecutionState::END_CALL_2, end_call_2::NUM_ROW, None)],
                None,
            ),
        ));
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let state_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let state_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        vec![
            (
                "state lookup, call_context write returndata_call_id".into(),
                state_lookup_0,
            ),
            (
                "state lookup, call_context write returndata_size".into(),
                state_lookup_1,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        current_state.returndata_call_id = current_state.call_id.clone();
        current_state
            .return_data
            .insert(current_state.call_id, vec![]);
        current_state.returndata_size = 0.into();

        //get call_context write rows.
        let call_context_write_row_0 = current_state.get_call_context_write_row(
            state::CallContextTag::ReturnDataCallId,
            current_state.returndata_call_id.into(),
            0,
        );
        let call_context_write_row_1 = current_state.get_call_context_write_row(
            state::CallContextTag::ReturnDataSize,
            current_state.returndata_size,
            current_state.returndata_call_id,
        );
        //generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        //insert lookup: Core ---> State
        core_row_1.insert_state_lookups([&call_context_write_row_0, &call_context_write_row_1]);

        let mut core_row_0 = ExecutionState::END_CALL_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            0.into()
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![call_context_write_row_0, call_context_write_row_1],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EndCall1Gadget {
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
        let mut current_state = WitnessExecHelper::new();
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
            ExecutionState::END_CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
