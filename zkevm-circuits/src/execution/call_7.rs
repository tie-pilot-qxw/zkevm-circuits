// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 4;

/// call_1..call_7为 CALL指令调用之前的操作，即此时仍在父CALL环境，
/// 读取接下来CALL需要的各种操作数，每个call_* gadget负责不同的操作数.
/// call_7负责接下来CALL指令的 gas，addr操作数，将stack_pointer置0执行新的CALL调用
/// ret_offset, ret_length操作数等CALL执行完成后再进行操作
/// |gas | addr | value | argsOffset | argsLength | retOffset | retLength
///
/// Call7 is the sixth step of opcode CALL.
/// After Call7, there should be execution states of the callee.
/// Algorithm overview:
///     1. read gas, addr from stack (temporarily not popped)
///     2. set call_context's storage_contract_addr = addr, caller = current code_addr
/// Table layout:
///     1. State lookup(stack read gas), src: Core circuit, target: State circuit table, 8 columns
///     2. State lookup(stack read addr), src: Core circuit, target: State circuit table, 8 columns
///     3. State lookup(call_context write storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     4. State lookup(call_context write caller), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call7Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call7Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_7"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_7
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        // 获取CALL指令的调用方地址
        let code_addr_cur = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        // CALL指令开始时 state_stamp值（即在call_1.rs中gadget生成witness之前的值）
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stack_pointer_prev = meta.query_advice(
            stack_pointer,
            // call_1， call_2 and call_3 don't change the stack_pointer value, so stack_pointer
            // of the last gadget equals to the stack_pointer just before the call operation.
            Rotation(-1 * NUM_ROW as i32),
        );

        // 计算即将执行的call_id
        let call_id_new = state_stamp_init.clone() + 1.expr();
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(0.expr()), // 此处的gas_left值与post_call保持一致
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            // stack pointer will become 0 after 6
            stack_pointer: ExpressionOutcome::Delta(-stack_pointer_prev.expr()),
            memory_chunk: ExpressionOutcome::To(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append stack constraints and call_context constraints
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            if i < 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    // the position of gas and addr are 0 and -1 respectively.
                    if i == 0 { 0 } else { -1 }.expr(),
                    false,
                ));
            } else {
                constraints.append(
                    &mut config.get_call_context_constraints(
                        meta,
                        entry.clone(),
                        i,
                        NUM_ROW,
                        true,
                        if i == 2 {
                            state::CallContextTag::StorageContractAddr as u8
                        } else {
                            state::CallContextTag::SenderAddr as u8
                        }
                        .expr(),
                        call_id_new.clone(),
                    ),
                );
            }
            // 记录每个state row的操作数
            let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // CALL指令需要的addr操作数
        let addr = operands[1].clone();
        // CALL指令调用的合约地址，与addr相同
        let storage_contract_addr = operands[2].clone();
        // CALL指令的调用方地址
        let sender_addr = operands[3].clone();

        constraints.extend([
            (
                "storage_contract_addr == addr hi".into(),
                storage_contract_addr[0].clone() - addr[0].clone(),
            ),
            (
                "storage_contract_addr == addr lo".into(),
                storage_contract_addr[1].clone() - addr[1].clone(),
            ),
            // 约束数据为CALL指令的调用方地址
            (
                "sender_addr == current code_addr ".into(),
                sender_addr[0].clone() * pow_of_two::<F>(128) + sender_addr[1].clone()
                    - code_addr_cur,
            ),
        ]);
        // append opcode constraint
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        let core_single_delta = CoreSinglePurposeOutcome {
            // call指令开始执行，所以next为0
            pc: ExpressionOutcome::To(0.expr()),
            // call指令开始执行，所以next为call_id_new
            call_id: ExpressionOutcome::To(call_id_new),
            // call指令开始执行，所以next为call的操作数addr
            code_addr: ExpressionOutcome::To(
                addr[0].clone() * pow_of_two::<F>(128) + addr[1].clone(),
            ),
            // tx_id 不变，因为还在同一笔交易执行中
            ..Default::default()
        };
        // append prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev state is CALL_6
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::CALL_6], NUM_ROW, vec![], None),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // gas 状态
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        // addr 状态
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        // 即将执行的call_id对应的合约地址（即上面的addr）
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        // 即将执行的call_id对应的调用方地址
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        // 将core 电路中数据在state电路中lookup
        vec![
            ("stack read gas".into(), stack_lookup_0),
            ("stack read addr".into(), stack_lookup_1),
            (
                "callcontext write storage_contract_addr".into(),
                call_context_lookup_0,
            ),
            (
                "callcontext write sender_addr".into(),
                call_context_lookup_1,
            ),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 从栈中读取gas，addr的值，Note: 未将操作数弹出栈
        let (stack_read_0, _gas) = current_state.get_peek_stack_row_value(trace, 1);
        let (stack_read_1, addr) = current_state.get_peek_stack_row_value(trace, 2);
        // 将CALL调用的合约地址生成state row, 写入state电路和core电路
        let call_context_write_row_0 = current_state.get_call_context_write_row(
            state::CallContextTag::StorageContractAddr,
            addr.into(),
            current_state.call_id_new,
        );
        // 将CALL指令的调用方地址生成state row，写入state 电路和core电路
        let call_context_write_row_1 = current_state.get_call_context_write_row(
            state::CallContextTag::SenderAddr,
            current_state.code_addr,
            current_state.call_id_new,
        );
        // 记录CALL指令调用所需的的合约addr和调用方地址
        current_state
            .storage_contract_addr
            .insert(current_state.call_id_new, addr);
        current_state
            .sender
            .insert(current_state.call_id_new, current_state.code_addr);

        // 更新stack pointer=0标识开始进行的CALL指令操作；
        current_state.stack_pointer = 0;
        // 在调用方的环境下生成core_row_1/0; 此时code_addr，call_id还未更新为将执行的CALL
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State； 将读取状态时生成的state rows写入core 电路，
        core_row_1.insert_state_lookups([
            &stack_read_0,
            &stack_read_1,
            &call_context_write_row_0,
            &call_context_write_row_1,
        ]);
        current_state.memory_chunk = 0;

        let core_row_0 = ExecutionState::CALL_7.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // 更新code_id, code_addr为CALL指令的状态，执行CALL指令
        current_state.call_id = current_state.call_id_new;
        current_state.code_addr = addr;

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                stack_read_0,
                stack_read_1,
                call_context_write_row_0,
                call_context_write_row_1,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call7Gadget {
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
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_6.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(state_stamp_init.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
