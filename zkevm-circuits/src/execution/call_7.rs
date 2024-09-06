// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{NUM_AUXILIARY, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: usize = 6;
const STAMP_INIT_COL_PREV_GADGET: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY;
const OPCODE_SELECTOR_IDX: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY;
const OPCODE_SELECTOR_IDX_START: usize = 0;

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
///     1. State1 lookup(stack read gas), src: Core circuit, target: State circuit table, 8 columns
///     2. State2 lookup(stack read addr), src: Core circuit, target: State circuit table, 8 columns
///     3. State3 lookup(call_context write storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     4. State4 lookup(call_context write sender addr), src: Core circuit, target: State circuit table, 8 columns
///     5. State5 lookup(call_context read callder addr), src: Core circuit, target: State circuit table, 8 columns
///     6. State6 lookup(call_context read sender addr), src: Core circuit, target: State circuit table, 8 columns
/// +-----+--------------+----------------+------------------------+----------------+
/// | cnt |              |               |                         |                |
/// +-----+--------------+---------------+-------------------------+----------------+
/// | 2 | STATE5(0..7)   | STATE6(8..15) |                         |                |
/// | 1 | STATE1(0..7)   | STATE2(8..15) | STATE3(16..23)          | STATE4(24..31) |
/// | 0 | DYNAMIC(0..17) | AUX(18..24)   | OPCODE_SELECTOR(25..27) |                |
/// +---+------- --------+--------------+--------------------------+----------------+
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        // 获取CALL指令的调用方地址
        let caller_code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        // CALL指令开始时 state_stamp值（即在call_1.rs中gadget生成witness之前的值）
        let state_stamp_init = meta.query_advice(
            config.vers[STAMP_INIT_COL_PREV_GADGET],
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
        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(0.expr()), // 此处的gas_left值与post_call保持一致
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            // stack pointer will become 0 after 6
            stack_pointer: ExpressionOutcome::Delta(-stack_pointer_prev.expr()),
            memory_chunk: ExpressionOutcome::To(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        let mut operands = vec![];
        let mut state_index = 0;
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            if i < 2 {
                // get stack_gas_read and stack_addr_read
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    // the position of gas and addr are 0 and -1 respectively.
                    if i == 0 { 0.expr() } else { -1.expr() },
                    false,
                ));
            } else {
                // get contract_addr_write and sender_addr_write
                let callcontext_tag = if i == 2 {
                    (state::CallContextTag::StorageContractAddr as u8).expr()
                } else {
                    (state::CallContextTag::SenderAddr as u8).expr()
                };
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    callcontext_tag,
                    call_id_new.clone(),
                ));
            }
            let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry.clone());
            operands.push([value_hi, value_lo]);
        }
        state_index += 4;

        // get caller_contract_addr
        let caller_contract_addr_entry = config.get_state_lookup_by_rotation(meta, Rotation(-2), 0);
        constraints.append(&mut config.get_call_context_constraints(
            meta,
            caller_contract_addr_entry.clone(),
            state_index,
            NUM_ROW,
            false,
            (state::CallContextTag::StorageContractAddr as u8).expr(),
            call_id.clone(),
        ));
        let (_, _, value_hi, value_lo, ..) =
            extract_lookup_expression!(state, caller_contract_addr_entry.clone());
        operands.push([value_hi, value_lo]);

        let sender_addr_entry = config.get_state_lookup_by_rotation(meta, Rotation(-2), 1);
        constraints.append(&mut config.get_call_context_constraints(
            meta,
            sender_addr_entry.clone(),
            state_index + 1,
            NUM_ROW,
            false,
            (state::CallContextTag::SenderAddr as u8).expr(),
            selector.select(&[call_id_new.clone(), call_id_new.clone(), call_id.clone()]),
        ));

        let (_, _, value_hi, value_lo, ..) =
            extract_lookup_expression!(state, sender_addr_entry.clone());
        operands.push([value_hi, value_lo]);

        // constraint contract addr and sender addr
        let stack_addr_read =
            operands[1][0].clone() * pow_of_two::<F>(128) + operands[1][1].clone();

        let contract_addr_write =
            operands[2][0].clone() * pow_of_two::<F>(128) + operands[2][1].clone();
        let sender_addr_write =
            operands[3][0].clone() * pow_of_two::<F>(128) + operands[3][1].clone();

        let caller_contract_addr_read =
            operands[4][0].clone() * pow_of_two::<F>(128) + operands[4][1].clone();
        let sender_addr_read =
            operands[5][0].clone() * pow_of_two::<F>(128) + operands[5][1].clone();

        constraints.extend([
            (
                "opcode==CALL or STATICCALL --> storage_contract_addr == stack_addr, opcode == DELEGATECALL ---> storage_contract_addr==caller.storage_contract_addr".into(),
                contract_addr_write.clone()
                    - selector.select(&[
                    stack_addr_read.clone(),
                    stack_addr_read.clone(),
                    caller_contract_addr_read.clone(),
                ]),
            ),
            (
                "opcode==CALL or STATICCALL --> sender_addr == caller.addr, opcode == DELEGATECALL --->  sender_addr== parent_addr(caller.sender_addr)".into(),
                sender_addr_write.clone()
                    - selector.select(&[
                    caller_contract_addr_read.clone(),
                    caller_contract_addr_read.clone(),
                    sender_addr_read.clone(),
                ]),
            ),
            // make sure the sender addr written is consistent with the sender addr obtained
            (
                "write sender_addr == read sender_addr".into(),
                sender_addr_write.clone() - sender_addr_read.clone()
            ),
        ]);
        // append opcode constraint
        constraints.push((
            "opcode".into(),
            opcode.clone()
                - selector.select(&[
                    OpcodeId::CALL.as_u8().expr(),
                    OpcodeId::STATICCALL.as_u8().expr(),
                    OpcodeId::DELEGATECALL.as_u8().expr(),
                ]),
        ));

        let core_single_delta = CoreSinglePurposeOutcome {
            // call指令开始执行，所以next为0
            pc: ExpressionOutcome::To(0.expr()),
            // call指令开始执行，所以next为call_id_new
            call_id: ExpressionOutcome::To(call_id_new),
            // call指令开始执行，所以next为call的操作数addr
            code_addr: ExpressionOutcome::To(stack_addr_read),
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

        let contract_addr_write_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let sender_addr_write_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        let caller_contract_addr_write_lookup = query_expression(meta, |meta| {
            config.get_state_lookup_by_rotation(meta, Rotation(-2), 0)
        });

        let sender_addr_read_lookup = query_expression(meta, |meta| {
            config.get_state_lookup_by_rotation(meta, Rotation(-2), 1)
        });

        // 将core 电路中数据在state电路中lookup
        vec![
            ("stack read gas".into(), stack_lookup_0),
            ("stack read addr".into(), stack_lookup_1),
            (
                "callcontext write storage_contract_addr".into(),
                contract_addr_write_lookup,
            ),
            (
                "callcontext write sender_addr".into(),
                sender_addr_write_lookup,
            ),
            (
                "callcontext read caller_contract_addr".into(),
                caller_contract_addr_write_lookup,
            ),
            (
                "callcontext read sender_addr".into(),
                sender_addr_read_lookup,
            ),
        ]
    }

    // 对于CALL和STATICCALLL, 被调用合约看到的合约地址为被调用合约自身的地址
    //  例如： A-----CALL/STATICALL---->B, B中看到的合约地址为B本身

    // 对于CALLCODE和DELEGATECALL，被调用合约看到的合约地址为调用者看到的合约地址
    //  例如：A-----CALLCODE/DELEGATECALL---->B，B看到的合约地址为A的合约地址
    //       A-----CALLCODE/DELEGATECALL---->B-------CALLCODE/DELEGATECALL---->C, C看到的合约地址为B看到的合约地址，B看到的合约地址为A的合约地址

    // 对于CALL和STATICCALLL和CALLCODE, 目标合约的看到的sender为调用者的地址
    //  例如： A-----CALL/STATICALL/CALLCODE---->B, B中看到的sender为A的地址

    // 对于DELEGATECALL，被调用的合约中看到的sender与调用者看到的sender是同一个
    //  例如：A-----DELEGATECALL---->B，B看到的sender与A看到的sender是同一个，即发送交易的用户的地址
    //       A-----DELEGATECALL---->B-------DELEGATECALL---->C, C看到的sender与B看到的sender是同一个，B看到的sender与A看到的是同一个，即发送交易的用户的地址
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let selector_index = match trace.op {
            OpcodeId::CALL => OPCODE_SELECTOR_IDX_START,
            OpcodeId::STATICCALL => OPCODE_SELECTOR_IDX_START + 1,
            OpcodeId::DELEGATECALL => OPCODE_SELECTOR_IDX_START + 2,
            _ => panic!("not CALL or STATICCALL or DELEGATECALL"),
        };

        // 从栈中读取gas，addr的值，Note: 未将操作数弹出栈
        let (stack_read_0, _gas) = current_state.get_peek_stack_row_value(trace, 1);
        let (stack_read_1, addr) = current_state.get_peek_stack_row_value(trace, 2);

        let (contract_addr, sender_addr) = match trace.op {
            OpcodeId::CALL | OpcodeId::STATICCALL => (
                addr,
                *current_state
                    .storage_contract_addr
                    .get(&current_state.call_id)
                    .unwrap(),
            ),
            OpcodeId::DELEGATECALL => (
                *current_state
                    .storage_contract_addr
                    .get(&current_state.call_id)
                    .unwrap(),
                *current_state.sender.get(&current_state.call_id).unwrap(),
            ),
            _ => panic!("opcode not CALL or STATICCALL or DELEGATECALL"),
        };

        let contract_addr_write_row = current_state.get_call_context_write_row(
            state::CallContextTag::StorageContractAddr,
            contract_addr,
            current_state.call_id_new,
        );

        // 将CALL指令的调用方地址生成state row，写入state 电路和core电路
        let sender_addr_write_row = current_state.get_call_context_write_row(
            state::CallContextTag::SenderAddr,
            sender_addr,
            current_state.call_id_new,
        );

        // 获取调用者的addr
        // 对于DELEGATECALL，contract_addr与caller_contract_addr一致
        // 对于CALL或者STATICCALL, sender_addr与caller_contract_addr一致
        // 下面CALL/STATICCALL对应的send_addr的读取只是为了辅助约束的编写，真正需要的是DELEGATECALL对应的sender_addr_read
        let caller_contract_addr_read_row = current_state
            .get_call_context_read_row_with_arbitrary_tag(
                state::CallContextTag::StorageContractAddr,
                *current_state
                    .storage_contract_addr
                    .get(&current_state.call_id)
                    .unwrap(),
                current_state.call_id,
            );

        // 为什么sender_addr的read操作要放在write后面?
        // 是因为state_circuit对于state_row有约束，read之前必然存在write的操作，对于DELEGATECALL来说，senders是caller_sender_addr，write一定是存在的，
        // 但是对于CALL/STATICCALL来说，call_id_new对应的sender_addr还未写入，所以要放在write后面
        // 放在后面并不影响约束
        let sender_addr_read_call_id = if trace.op == OpcodeId::DELEGATECALL {
            current_state.call_id
        } else {
            current_state.call_id_new
        };
        let sender_addr_read_row = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::SenderAddr,
            sender_addr,
            sender_addr_read_call_id,
        );

        // 记录CALL指令调用所需的的合约addr和调用方地址
        current_state
            .storage_contract_addr
            .insert(current_state.call_id_new, contract_addr);

        current_state
            .sender
            .insert(current_state.call_id_new, sender_addr);

        // 更新stack pointer=0标识开始进行的CALL指令操作；
        current_state.stack_pointer = 0;

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_state_lookups([&caller_contract_addr_read_row, &sender_addr_read_row]);

        // 在调用方的环境下生成core_row_1/0; 此时code_addr，call_id还未更新为将执行的CALL
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State； 将读取状态时生成的state rows写入core 电路，
        core_row_1.insert_state_lookups([
            &stack_read_0,
            &stack_read_1,
            &contract_addr_write_row,
            &sender_addr_write_row,
        ]);
        current_state.memory_chunk = 0;

        let mut core_row_0 = ExecutionState::CALL_7.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // tag selector
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

        // 更新code_id, code_addr为CALL指令的状态，执行CALL指令
        current_state.call_id = current_state.call_id_new;
        current_state.code_addr = addr;

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![
                stack_read_0,
                stack_read_1,
                contract_addr_write_row,
                sender_addr_write_row,
                caller_contract_addr_read_row,
                sender_addr_read_row,
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
        let caller_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        current_state
            .storage_contract_addr
            .insert(current_state.call_id, caller_addr);

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
