// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{
    GAS_LEFT_IDX, MEMORY_CHUNK_PREV_IDX, NUM_AUXILIARY, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
};
use crate::execution::{
    call_3, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 2;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at post_call

const STATE_LOOKUP_IDX: usize = 0;

const STAMP_INIT_COL: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY;

const MEMORY_CHUNK_PREV_COL: usize = STAMP_INIT_COL + MEMORY_CHUNK_PREV_IDX;

const OPCODE_SELECTOR_IDX: usize = MEMORY_CHUNK_PREV_COL + 1;

const GAS_LEFT_COL: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX;

const OPCODE_SELECTOR_IDX_START: usize = 0;

/// call_1..call_7为 CALL指令调用之前的操作，即此时仍在父CALL环境，
/// 读取接下来CALL需要的各种操作数，每个call_* gadget负责不同的操作数.
/// call_2读取value操作数；
/// |gas | addr | value | argsOffset | argsLength | retOffset | retLength
///
///
/// Call2 is the second step of opcode CALL
/// Algorithm overview:
/// 1. read value from stack (temporarily not popped)
/// 2. write value to call_context
/// Table layout:
///     STATE1:  State lookup(stack read value), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(call_context write value), src: Core circuit, target: State circuit table, 8 columns
///     STATE_STAMP_INIT: the state stamp just before CALL1, which is obtained from the previous execution state (CALL1) and will be used by the next execution states
///     OPCODE_SELECTOR: Selector for CALL, STATICALL, DELEGATECALL， 3 columns
/// +---+------------------------+------------------+---------------------+----------------+----------------------+------------------------+
/// |cnt|                        |                 |                      |                |                     |                         |
/// +---+------------------------+-----------------+----------------------+----------------+---------------------+-------------------------+
/// | 1 | STATE1(0..7)           | STATE2(8..15).  |                      |                |                     |                         |
// | 0 | DYNA_SELECTOR(0..17)    | AUX(18..24)     | STATE_STAMP_INIT(25) |                |MEMORY_CHUNK_PREV(27)| OPCODE_SELECTOR(28..30) |
/// +---+------------------------+-----------------+----------------------+----------------+--------------------+--------------------------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call2Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call2Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL2"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_2
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_3::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let state_stamp_init =
            meta.query_advice(config.vers[STAMP_INIT_COL], Rotation(-1 * NUM_ROW as i32));
        let call_id_new = state_stamp_init.clone() + 1.expr();
        let stamp_init_for_next_gadget =
            meta.query_advice(config.vers[STAMP_INIT_COL], Rotation::cur());
        let memory_chunk_prev_for_next =
            meta.query_advice(config.vers[MEMORY_CHUNK_PREV_COL], Rotation::cur());
        let memory_chunk_prev = meta.query_advice(
            config.vers[MEMORY_CHUNK_PREV_COL],
            Rotation(-1 * NUM_ROW as i32),
        );

        let mut constraints = vec![];

        // Create a simple selector with opcode
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 1], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 2], Rotation::cur()),
        ]);
        // Add constraints for the selector.
        constraints.extend(selector.get_constraints());

        // append auxiliary constraints
        let state_stamp_dela = selector.select(&[
            STATE_STAMP_DELTA.expr(),
            (STATE_STAMP_DELTA - 1).expr(),
            STATE_STAMP_DELTA.expr(),
        ]);
        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(0.expr()), // 此处的gas_left值与CALL1-3保持一致
            refund: ExpressionOutcome::Delta(0.expr()),
            // 读取value，记录call_id对应的value 两次操作，所以stamp delta=2
            state_stamp: ExpressionOutcome::Delta(state_stamp_dela),
            // 未进行出栈操作，约束当前stack pointer与上个gadget相同
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // append state constraints
        let mut operands = vec![];

        // contract state lookup entry[0]
        let entry = config.get_state_lookup(meta, STATE_LOOKUP_IDX);
        constraints.extend(config.get_read_value_constraints_by_call(
            meta,
            entry.clone(),
            NUM_ROW,
            &selector,
            STATE_LOOKUP_IDX,
        ));
        let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry);
        operands.push([value_hi, value_lo]);

        // contract state lookup entry[1] (call context write)
        let entry = config.get_state_lookup(meta, STATE_LOOKUP_IDX + 1);
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let stamp_expr = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        // STATICCALL only performs one write operation，while CALL and STATICCALL both perform one read operation and one write operation.
        let stamp = selector.select(&[
            stamp_expr.clone() + (STATE_LOOKUP_IDX + 1).expr(),
            stamp_expr.clone() + STATE_LOOKUP_IDX.expr(),
            stamp_expr.clone() + (STATE_LOOKUP_IDX + 1).expr(),
        ]);
        constraints.extend(config.get_state_constraints(
            entry.clone(),
            STATE_LOOKUP_IDX + 1,
            (state::Tag::CallContext as u8).expr(),
            call_id_new.clone(),
            0.expr(),
            (state::CallContextTag::Value as u8).expr(),
            stamp,
            1.expr(),
        ));
        let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry);
        operands.push([value_hi, value_lo]);

        // append constraints for state_lookup's values
        // 因为两个state 状态记录的都是value操作数，所以两个操作数的高、低位都相同
        constraints.extend([
            (
                "value equal hi".into(),
                operands[0][0].clone() - operands[1][0].clone(),
            ),
            (
                "value equal lo".into(),
                operands[0][1].clone() - operands[1][1].clone(),
            ),
        ]);
        // append opcode constraint
        constraints.extend([
            (
                "opcode".into(),
                opcode
                    - selector.select(&[
                        OpcodeId::CALL.as_u8().expr(),
                        OpcodeId::STATICCALL.as_u8().expr(),
                        OpcodeId::DELEGATECALL.as_u8().expr(),
                    ]),
            ),
            // append constraint for the next execution state's stamp_init
            (
                "state_init_for_next_gadget correct".into(),
                stamp_init_for_next_gadget - state_stamp_init,
            ),
            (
                "memory_chunk_prev_for_next correct".into(),
                memory_chunk_prev_for_next - memory_chunk_prev,
            ),
        ]);
        // append prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev execution state is CALL_1
        // next execution state is CALL_3
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_1],
                NUM_ROW,
                vec![(ExecutionState::CALL_3, call_3::NUM_ROW, None)],
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
        // 获取core电路value值，与state电路lookup
        let stack_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, STATE_LOOKUP_IDX));
        let call_context_lookup = query_expression(meta, |meta| {
            config.get_state_lookup(meta, STATE_LOOKUP_IDX + 1)
        });

        vec![
            ("stack read value".into(), stack_lookup),
            ("callcontext write value".into(), call_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (state_read_row, state_write_row, value, selector_index) = match trace.op {
            OpcodeId::CALL => {
                let (stack_read_row, value) = current_state.get_peek_stack_row_value(trace, 3);
                let call_context_write_row = current_state.get_call_context_write_row(
                    state::CallContextTag::Value,
                    value,
                    current_state.call_id_new,
                );
                (
                    stack_read_row,
                    call_context_write_row,
                    value,
                    OPCODE_SELECTOR_IDX_START,
                )
            }
            OpcodeId::STATICCALL => {
                let value = U256::zero();
                let call_context_write_row = current_state.get_call_context_write_row(
                    state::CallContextTag::Value,
                    value,
                    current_state.call_id_new,
                );
                (
                    state::Row::default(),
                    call_context_write_row,
                    value,
                    OPCODE_SELECTOR_IDX_START + 1,
                )
            }
            OpcodeId::DELEGATECALL => {
                let parent_value = *current_state.value.get(&current_state.call_id).unwrap();
                let call_context_read_row = current_state
                    .get_call_context_read_row_with_arbitrary_tag(
                        state::CallContextTag::Value,
                        parent_value,
                        current_state.call_id,
                    );
                let call_context_write_row = current_state.get_call_context_write_row(
                    state::CallContextTag::Value,
                    parent_value,
                    current_state.call_id_new,
                );
                (
                    call_context_read_row,
                    call_context_write_row,
                    parent_value,
                    OPCODE_SELECTOR_IDX_START + 2,
                )
            }
            _ => panic!("opcode not CALL or STATICCALL or DELEGATECALL"),
        };
        // update current_state's value
        current_state.value.insert(current_state.call_id_new, value);
        // generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        core_row_1.insert_state_lookups([&state_read_row, &state_write_row]);

        let mut core_row_0 = ExecutionState::CALL_2.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // here we use the property that call_id_new == state_stamp + 1,
        // where stamp_init is the stamp just before call operation is
        // executed (instead of before the call_2 gadget).
        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(core_row_0[STAMP_INIT_COL], stamp_init.into());
        // core_row_0写入memory_chunk_prev, 向下传至memory gas计算部分
        assign_or_panic!(
            core_row_0[MEMORY_CHUNK_PREV_COL],
            current_state.memory_chunk_prev.into()
        );
        // CALL1到CALL4时还未进行gas计算，此时gas_left为trace.gas
        core_row_0[GAS_LEFT_COL] = Some(trace.gas.into());

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

        // staticcall要读取的默认的零行
        let state_rows = if trace.op == OpcodeId::STATICCALL {
            vec![state_write_row]
        } else {
            vec![state_read_row, state_write_row]
        };
        Witness {
            core: vec![core_row_1, core_row_0],
            state: state_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call2Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
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
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(state_stamp_init.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_3.into_exec_state_core_row(
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
