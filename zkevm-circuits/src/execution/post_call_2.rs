// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;

use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    end_call_2, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, copy, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: usize = 4;
const STACK_POINTER_DELTA: i32 = -6;
const PC_DELTA: u64 = 1;
const START_COL_IDX: usize = 11;

/// 当evm CALL指令调用结束后，正常返回或异常出错时（如：REVERT，STOP）时，调用当前 gadget
/// post_call_2 is one of the last steps of opcode CALL, which is
/// located after the callee's all execution states.
///
/// Algorithn overview:
///     1. read ret_offset and ret_len from stack
///     2. read returndata_call_id from call_context
///     3. copy bytes from returndata to memory[ret_offset:ret_offset+ret_len]
///     4. write success flag to stack
/// Table layout:
///     1. STATE1: State lookup(stack read ret_offset), src: Core circuit, target: State circuit table, 8 columns
///     2. STATE2: State lookup(stack read ret_len), src: Core circuit, target: State circuit table, 8 columns
///     3. STATE3: State lookup(call_context read returndata_call_id), src: Core circuit, target: State circuit table, 8 columns
///     4. STATE4: State lookup(stack write success), src: Core circuit, target: State circuit table, 8 columns
///     5. COPY: Copy lookup(copy bytes from returndata to memory), src:Core circuit, target:Copy circuit table, 11 columns
///     6. COPY_LEN: the actual number of bytes copied, which is equal to copy lookup's len, 1 column
///     7. LEN_INV: the inverse of copy lookup's len, 1 column
///     8. COPY_PADDING_LEN: only used to construct a lookup entry to arithmetic circuit (tag: length), 1 column
///     
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY(11) | COPY_LEN(1)| LEN_INV(1)| COPY_PADDING_LEN(1)  |
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
///
/// Note:
///     1. The actual number of bytes copied might be smaller than ret_len, and we use length arithmetic to handle the problem.
///     2. According to Ethereum, the exceeding parts won't be padded with 0, so we don't need ZERO_COPY lookup.
pub struct PostCall2Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PostCall2Gadget<F>
{
    fn name(&self) -> &'static str {
        "POST_CALL_2"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::POST_CALL_2
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
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());
        let success = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );

        let copy_entry = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            // len*2 因为一份return_data数据记录了两次state rows
            // first: 记录从return_data copy的len字节的数据
            // second: 记录将copy 的len字节数据写入memory区域
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            ),
            // 弹出7个栈上元素，push 1个栈上元素，所以栈帧相差6
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append stack constraints and call_context constraints
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            if i != 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    // the position of ret_offset, ret_len and success are -5, -6 and -6 respectively.
                    if i == 0 { -5 } else { -6 }.expr(),
                    // i==3的state row为将Call调用的结果入栈，所以write=true
                    i == 3,
                ));
            } else {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    (state::CallContextTag::ReturnDataCallId as u8).expr(),
                    0.expr(),
                ));
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state lookup's values
        constraints.extend([
            // evm 执行环境中，u128 bit足以表示 ret_offset，ret_len，returndata_call_id，Call执行结果
            // 所以对应字段的operands高128bit约束为0
            ("ret_offset hi".into(), operands[0][0].clone()),
            ("ret_len hi".into(), operands[1][0].clone()),
            ("returndata_call_id hi".into(), operands[2][0].clone()),
            ("success write hi".into(), operands[3][0].clone()),
            // 约束不同Cell的中填写的Call执行结果相同。
            ("success write lo".into(), operands[3][1].clone() - success),
        ]);

        let ret_offset = operands[0][1].clone();
        let returndata_call_id = operands[2][1].clone();
        //append copy constraints
        let copy_len_lo = meta.query_advice(config.vers[START_COL_IDX], Rotation(-2));
        let len_lo_inv = meta.query_advice(config.vers[START_COL_IDX + 1], Rotation(-2));
        let is_zero_len = SimpleIsZero::new(&copy_len_lo, &len_lo_inv, String::from("copy_len_lo"));

        constraints.append(&mut is_zero_len.get_constraints());

        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 3));
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Returndata,
            returndata_call_id,
            0.expr(),
            // +1.expr() after state row is generated, the stamp+=1 affected, thus subsequent copy_row start at stamp+=1.
            stamp.clone() + 1.expr(),
            copy::Tag::Memory,
            call_id_cur,
            ret_offset,
            stamp + copy_len_lo.clone() + 1.expr(),
            None,
            copy_len_lo,
            is_zero_len.expr(),
            None,
            copy_entry,
        ));
        // prev state is END_CALL
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::POST_CALL_1], NUM_ROW, vec![], None),
        ));
        // append opcode constraint
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // ret_offset state row
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        // ret_length state row
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        // returndata_callid state row
        let call_context_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        // return_success(Call 指令的执行结果) state row
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        // copy return data to memory
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));

        //TODO:confirm whether the following is correct
        let _arithmetic_lookup = query_expression(meta, |meta| {
            let ret_offset_state_entry = config.get_state_lookup(meta, 0);
            let ret_len_state_entry = config.get_state_lookup(meta, 1);

            let (_, _, _, ret_offset, _, _, _, _) =
                extract_lookup_expression!(state, ret_offset_state_entry);
            let (_, _, _, ret_len, _, _, _, _) =
                extract_lookup_expression!(state, ret_len_state_entry);
            let returndata_size = meta.query_advice(
                config.vers[NUM_STATE_HI_COL
                    + NUM_STATE_LO_COL
                    + NUM_AUXILIARY
                    + end_call_2::RETURNDATA_SIZE_COL_IDX],
                Rotation(-1 * NUM_ROW as i32),
            );
            let copy_len = meta.query_advice(config.vers[START_COL_IDX], Rotation(-2));
            let copy_padding_len = meta.query_advice(config.vers[START_COL_IDX + 2], Rotation(-2));

            LookupEntry::Arithmetic {
                tag: (arithmetic::Tag::Length as u8).expr(),
                values: [
                    ret_len,
                    ret_offset,
                    returndata_size,
                    0.expr(),
                    copy_len,
                    copy_padding_len,
                    0.expr(),
                    0.expr(),
                ],
            }
        });

        vec![
            ("stack read ret_offset".into(), stack_lookup_0),
            ("stack read ret_length".into(), stack_lookup_1),
            (
                "callcontext read returndata_call_id".into(),
                call_context_lookup,
            ),
            ("stack write success".into(), stack_lookup_2),
            ("copy lookup".into(), copy_lookup),
            // ("arithmetic lookup".into(), arithmetic_lookup),
            // TODO add arithmetic lookup
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        //generate stack read rows
        let (stack_read_0, ret_offset) = current_state.get_peek_stack_row_value(trace, 6);
        let (stack_read_1, ret_length) = current_state.get_peek_stack_row_value(trace, 7);

        // CALL指令使用了7个操作数，在CALL1..CALL4已读取其它字段，post_call读取ret_offset, ret_length后
        // 将数据全部弹出栈
        current_state.stack_pointer -= 7;
        //generate call_context read row
        let call_context_read_row = current_state.get_returndata_call_id_row(false);
        //generate stack_write row
        let stack_write_row =
            current_state.get_push_stack_row(trace, U256::from(current_state.return_success as u8));
        //generate copy rows and memory write rows
        let (copy_rows, mut state_rows, copy_len) =
            current_state.get_call_return_data_copy_rows::<F>(ret_offset, ret_length);
        //generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        // insert lookup: Core ---> Copy
        if copy_len == 0 {
            core_row_2.insert_copy_lookup(
                0,
                &copy::Row {
                    byte: 0.into(),
                    src_type: copy::Tag::default(),
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::default(),
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: 0.into(),
                    len: 0.into(),
                    acc: 0.into(),
                },
            );
        } else {
            core_row_2.insert_copy_lookup(0, copy_rows.get(0).unwrap());
        }
        //calculate and assign copy_len, copy_len_inv and copy_padding_len
        let copy_len_inv = U256::from_little_endian(
            F::from_u128(copy_len as u128)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        let copy_padding_len = if U256::from(copy_len) < ret_length {
            ret_length - U256::from(copy_len)
        } else {
            0.into()
        };
        let column_values = [copy_len.into(), copy_len_inv, copy_padding_len];
        for i in 0..3 {
            assign_or_panic!(core_row_2[i + START_COL_IDX], column_values[i]);
        }
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_read_0,
            &stack_read_1,
            &call_context_read_row,
            &stack_write_row,
        ]);
        let core_row_0 = ExecutionState::POST_CALL_2.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        state_rows.extend([
            stack_read_0,
            stack_read_1,
            call_context_read_row,
            stack_write_row,
        ]);

        //generate arithmetic rows
        let (arithmetic_rows, _) = operation::length::gen_witness::<F>(vec![
            ret_offset,
            ret_length,
            current_state.returndata_size,
        ]);

        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            arithmetic: arithmetic_rows, // todo, implement length arithmetic and memory_expansion arithmetic
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(PostCall2Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::{MEMORY_CHUNK_PREV_IDX, STACK_POINTER_IDX};
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
            call_id: 0x01,
            returndata_call_id: 0x50,
            returndata_size: U256::from(10),
            return_success: true,
            stack_top: Some(1.into()),
            ..WitnessExecHelper::new()
        };
        let value_vec = [0x12; 10];
        current_state.return_data.insert(0x50, value_vec.to_vec());

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::POST_CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] = Some(1.into()); // let success == true
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX] =
                Some(10.into()); // let the previous gadgets(end_call)'s returndata_size cell's value equals to returndata_size
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
