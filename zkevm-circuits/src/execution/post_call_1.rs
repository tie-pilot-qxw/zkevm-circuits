// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;

use crate::constant::{NUM_AUXILIARY, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use crate::execution::end_call_2::RETURNDATA_SIZE_COL_IDX;
use crate::execution::{
    post_call_2, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 3;

const RETURN_DATA_SUCCESS_COL: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY;
const RETURN_DATA_SIZE_COL: usize = RETURN_DATA_SUCCESS_COL + RETURNDATA_SIZE_COL_IDX;

const OPCODE_SELECTOR_IDX: usize = RETURN_DATA_SIZE_COL + 1;
const OPCODE_SELECTOR_IDX_START: usize = 0;

/// POST_CALL_1 用于处理gas相关的call_context操作，在call_6时write trace.gas 和 trace.gas_cost
/// 在POST_CALL_1时read call_context, 从而完成 POST_CALL_1的gas约束
///
/// post_call_1 is one of the last steps of opcode CALL, which is
/// located after the callee's all execution states.
/// Table layout:
///     cnt == 0: RETURN_SUCCESS, RETURNDATA_SIZE for next gadget
///     cnt == 1:
///         CALLCONTEXT_READ_0: read trace.gas
///         CALLCONTEXT_READ_1: read trace.gas_cost
/// +-----+---------------------+---------------------+---------------------+----------------------+--------------------------+
/// | cnt |                     |                     |                     |                      |                          |
/// +-----+---------------------+---------------------+---------------------+----------------------+--------------------------+
/// | 1   | CALLCONTEXT_READ_0 | CALLCONTEXT_READ_1   | CALLCONTEXT_READ_2  |                      |                          |
/// | 0   | DYNA_SELECTOR       | AUX                 | RETURN_SUCCESS (25) | RETURNDATA_SIZE (27) | OPCODE_SELECTOR(28..30)  |
/// +-----+---------------------+---------------------+---------------------+----------------------+--------------------------+
pub struct PostCall1Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PostCall1Gadget<F>
{
    fn name(&self) -> &'static str {
        "POST_CALL_1"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::POST_CALL_1
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, post_call_2::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // Create a simple selector with opcode
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 1], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 2], Rotation::cur()),
        ]);
        // Add constraints for the selector.
        constraints.extend(selector.get_constraints());

        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        // 1. call_context constraints
        let mut operands = vec![];
        for i in 0..3 {
            // 约束填入core电路的state 状态值
            let entry = config.get_state_lookup(meta, i);
            constraints.append(
                &mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    if i == 0 {
                        state::CallContextTag::ParentGas as u8
                    } else if i == 1 {
                        state::CallContextTag::ParentGasCost as u8
                    } else {
                        state::CallContextTag::ParentMemoryChunk as u8
                    }
                    .expr(),
                    call_id.clone(),
                ),
            );

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            constraints.push(("value_hi == 0".into(), value_hi));
            operands.push(value_lo);
        }

        // 2. opcode and state_init constraints
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.push((
            "opcode".into(),
            opcode
                - selector.select(&[
                    OpcodeId::CALL.as_u8().expr(),
                    OpcodeId::STATICCALL.as_u8().expr(),
                    OpcodeId::DELEGATECALL.as_u8().expr(),
                ]),
        ));

        // 3. return_success and return_data_size constraints
        let return_success_for_next =
            meta.query_advice(config.vers[RETURN_DATA_SUCCESS_COL], Rotation::cur());
        let return_data_size_for_next =
            meta.query_advice(config.vers[RETURN_DATA_SIZE_COL], Rotation::cur());
        let return_success_prev = meta.query_advice(
            config.vers[RETURN_DATA_SUCCESS_COL],
            Rotation(-1 * NUM_ROW as i32),
        );
        let return_data_size_prev = meta.query_advice(
            config.vers[RETURN_DATA_SIZE_COL],
            Rotation(-1 * NUM_ROW as i32),
        );

        constraints.extend([
            (
                "return_success".into(),
                return_success_for_next.clone() - return_success_prev,
            ),
            (
                "return_data_size".into(),
                return_data_size_for_next - return_data_size_prev,
            ),
        ]);

        // 4. auxiliary constraints

        // 4.1 if call is success, then cur_step_gas - prev_step_gas = CALL_OP_GAS - CALL_OP_GAS_COST
        // 4.2 if call not success, then cur_step_gas = CALL_OP_GAS - CALL_OP_GAS_COST
        let gas_cost = operands[0].clone() - operands[1].clone();
        let cur_gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let prev_gas_left = meta.query_advice(
            config.get_auxiliary().gas_left,
            Rotation(-1 * NUM_ROW as i32),
        );
        constraints.push((
            "gas left prev - cur".into(),
            cur_gas_left - return_success_for_next * prev_gas_left - gas_cost,
        ));

        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Any,
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(operands[2].clone()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // 5. prev and current core constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev state is END_CALL, next state is POST_CALL_2
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::END_CALL_2],
                NUM_ROW,
                vec![(ExecutionState::POST_CALL_2, post_call_2::NUM_ROW, None)],
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
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));

        // 将core 电路中数据在state电路中lookup
        vec![
            ("ParentTraceGas read".into(), call_context_lookup_0),
            ("ParentTraceGasCost read".into(), call_context_lookup_1),
            ("ParentMemoryChunk read".into(), call_context_lookup_2),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 到这里说明上一个call已经结束，需要恢复上一个call的状态（主要是memory_chunk）
        current_state.memory_chunk = *current_state
            .parent_memory_chunk
            .get(&current_state.call_id)
            .unwrap();
        let selector_index = match trace.op {
            OpcodeId::CALL => OPCODE_SELECTOR_IDX_START,
            OpcodeId::STATICCALL => OPCODE_SELECTOR_IDX_START + 1,
            OpcodeId::DELEGATECALL => OPCODE_SELECTOR_IDX_START + 2,
            _ => panic!("opcode not CALL or STATICCALL or DELEGATECALL"),
        };

        let parent_trace_gas = current_state.parent_gas[&current_state.call_id];
        let parent_trace_gas_cost = current_state.parent_gas_cost[&current_state.call_id];
        let parant_memory_chunk = current_state.parent_memory_chunk[&current_state.call_id];

        println!(
            "post call1, get call_id:{:?}, parent_memory_chunk:{:x}",
            current_state.call_id, parant_memory_chunk
        );

        let call_context_read_0 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentGas,
            parent_trace_gas.into(),
            current_state.call_id.into(),
        );

        let call_context_read_1 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentGasCost,
            parent_trace_gas_cost.into(),
            current_state.call_id.into(),
        );

        let call_context_read_2 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentMemoryChunk,
            parant_memory_chunk.into(),
            current_state.call_id.into(),
        );

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([
            &call_context_read_0,
            &call_context_read_1,
            &call_context_read_2,
        ]);

        let mut core_row_0 = ExecutionState::POST_CALL_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        assign_or_panic!(
            core_row_0[RETURN_DATA_SUCCESS_COL],
            (current_state.return_success as u8).into()
        );

        assign_or_panic!(
            core_row_0[RETURN_DATA_SIZE_COL],
            current_state.returndata_size
        );

        // opcodeid selector
        simple_selector_assign(
            &mut core_row_0,
            [
                OPCODE_SELECTOR_IDX,
                OPCODE_SELECTOR_IDX + 1,
                OPCODE_SELECTOR_IDX + 2,
            ],
            selector_index,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                call_context_read_0,
                call_context_read_1,
                call_context_read_2,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(PostCall1Gadget {
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
        let stack = Stack::from_slice(&[
            0x05.into(),
            0x2222.into(),
            0x04.into(),
            0x1111.into(),
            0x01.into(),
            0x1234.into(),
            0x01.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let state_stamp_init = 3;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;
        current_state
            .parent_gas
            .insert(current_state.call_id, 0u64.into());
        current_state
            .parent_gas_cost
            .insert(current_state.call_id, 0u64.into());
        current_state
            .parent_memory_chunk
            .insert(current_state.call_id, 0u64.into());

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let row = ExecutionState::END_CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::POST_CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            //row.pc = 0.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
