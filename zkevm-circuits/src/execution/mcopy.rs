// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;
use crate::constant::{
    GAS_LEFT_IDX, LENGTH_IDX, MEMORY_CHUNK_PREV_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY,
};
use crate::execution::ExecutionState::MEMORY_GAS;
use crate::execution::{
    memory_gas, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Overview:
///   MCOPY is mainly used to read bytes of specified length from Memory and write them into Memeory
///   1. pop three elements from the top of the stack
///      stack_pop0: destOffset(for Memory, the starting copy length)
///      stack_pop1: offset(for Memory, the starting copy length)
///      stack_pop2: length(the length of the Memory to be copied)
///   2. `memory[destOffset:destOffset+length] =  memory[offset:offset+length]`
///
///  Note:
///   Memory operations assume that the length of the memory is sufficient and will not cause panic.
///   It's guaranteed by Ethereum that dst + i doesn't overflow
///   reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L51,
//               https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory.go#L107
///
///
/// Table layout:
///     COPY: src:State circuit, target:State circuit table, 11 columns
///     ARITH: memory expansion arithmatic lookup, 5 columns
///     NEW_MEMORY_SIZE is `length + offset`
///     MEMORY_CHUNK_PREV is the previous memory chunk
///     LENGTH is the opcode input parameter
///     LENGTH_INV:  original codecopy length's multiplicative inverse
/// +---+-------+-------+------------------------+--------------------------------------------------------+
/// |cnt| 8 col | 8 col |              8 col     | 8col                                                   |
/// +---+-------+-------+------------------------+--------------------------------------------------------+
/// | 2 |  COPY   | ARITH(5)
/// | 1 | STATE0| STATE1|        STATE2          |                                                        |
/// | 0 | DYNA_SELECTOR   | AUX |LENGTH_INV      |  NEW_MEMORY_SIZE(26) |MEMORY_CHUNK_PREV(27)|LENGTH(28) |
/// +---+-------+-------+------------------------+--------------------------------------------------------+

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -3;
pub struct MCopyGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MCopyGadget<F>
{
    fn name(&self) -> &'static str {
        "MCOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MCOPY
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, memory_gas::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let copy_lookup_entry = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, copy_lookup_len, _) =
            extract_lookup_expression!(copy, copy_lookup_entry.clone());

        let mut constraints = vec![];

        // stack constraints
        // index0: dst_offset, index1: offset, index2: len
        let mut copy_stamp_start = 0.expr();
        let mut stack_pop_values = vec![];
        for i in 0..3 {
            let state_entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                state_entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, stamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);
            stack_pop_values.push([value_hi, value_lo]);
            if i == 2 {
                copy_stamp_start = stamp;
            }
        }

        // get length
        let length = stack_pop_values[2][1].clone();
        let length_inv = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );

        // constraint that length_inv is length's inverse
        let length_is_zero = SimpleIsZero::new(&length, &length_inv, String::from("length_lo"));
        constraints.extend(length_is_zero.get_constraints());

        //  code copy constraints
        constraints.extend(config.get_copy_constraints(
            copy::Tag::Memory,
            call_id.clone(),
            stack_pop_values[1][1].clone(), // stack top1 value_lo
            copy_stamp_start.clone() + 1.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_pop_values[0][1].clone(), // stack top0 value_lo
            copy_stamp_start.clone() + 1.expr() + length.clone(), // writing to memory happens after reading from memory
            None,
            length.clone(), // stack top2 value_lo
            length_is_zero.expr(),
            None,
            copy_lookup_entry.clone(),
        ));

        // because the values of destOffset, offset, and length are all in the u64 range, all value_hi is 0
        constraints.extend([
            (
                "stack top0 value_hi = 0".into(),
                stack_pop_values[0][0].clone(),
            ),
            (
                "stack top1 value_hi = 0".into(),
                stack_pop_values[1][0].clone(),
            ),
            (
                "stack top2 value_hi = 0".into(),
                stack_pop_values[2][0].clone(),
            ),
        ]);

        // memory chunk
        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (
            arith_memory_expand_tag,
            [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size],
        ) = extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 2));

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - is_zero_len.expr()) in state lookup"
                .into(),
            (stack_pop_values[0][1].clone() + length.clone()) *(1.expr() - length_is_zero.expr())
                - offset_bound.clone(),
        ));

        constraints.push((
            "memory_chunk_prev in arithmetic = in auxiliary".into(),
            memory_chunk_prev.clone()
                - meta.query_advice(
                    config.get_auxiliary().memory_chunk,
                    Rotation(-1 * NUM_ROW as i32).clone(),
                ),
        ));

        let memory_chunk_to = expansion_tag.clone() * access_memory_size.clone()
            + (1.expr() - expansion_tag.clone()) * memory_chunk_prev;

        // next state constraints
        let memory_size_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation::cur(),
        );
        constraints.push((
            "memory_size_for_next ==  (mem_off + length) * (1 - is_zero_len.expr()) in state lookup".into(),
            (stack_pop_values[0][1].clone() + length.clone()) * (1.expr() - length_is_zero.expr())
                - memory_size_for_next.clone(),
        ));

        let memory_chunk_prev_for_next = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            Rotation::cur(),
        );
        constraints.push((
            "memory_chunk_prev_for_next == memory_chunk_prev in auxiliary".into(),
            memory_chunk_prev_for_next
                - meta.query_advice(
                    config.get_auxiliary().memory_chunk,
                    Rotation(-1 * NUM_ROW as i32).clone(),
                ),
        ));

        let length_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX],
            Rotation::cur(),
        );
        constraints.push((
            "length_for_next == length in state lookup".into(),
            length_for_next - length.clone(),
        ));

        // Add constraints for arithmetic tag.
        constraints.extend(vec![(
            "arithmetic tag is MemoryExpansion".into(),
            arith_memory_expand_tag.clone() - (arithmetic::Tag::MemoryExpansion as u8).expr(),
        )]);

        // auxiliary constraints
        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + (copy_lookup_len.clone() * 2.expr()),
            ),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()), // call data copy最终的gas有memory_copier_gas决定
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta));

        // pc后移至memory_copier_gas后变化
        let core_single_delta = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(MEMORY_GAS, memory_gas::NUM_ROW, None)],
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
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));

        // arithmetic memory_expansion lookup
        let arith_memory =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 2));

        vec![
            ("state lookup, stack pop dst_offset".into(), stack_lookup_0),
            (
                "state lookup, stack pop lookup offset".into(),
                stack_lookup_1,
            ),
            (
                "state lookup, stack pop lookup length".into(),
                stack_lookup_2,
            ),
            ("memory copy lookup".into(), copy_lookup),
            (
                "arithmetic memory expansion tiny lookup".into(),
                arith_memory,
            ),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::MCOPY);

        // get dstOffset、offset、length from stack top
        let (stack_dest_offset_row, dest_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_offset_row, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_length_row, length) = current_state.get_pop_stack_row_value(&trace);

        // get memory copy rows and state read/write rows
        let (copy_rows, state_rows) =
            current_state.get_mcopy_rows::<F>(trace, dest_offset, offset, length);

        // core row2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_copy_lookup(0, &copy_rows[0]);

        // memory expansion
        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            dest_offset + length
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);
        core_row_2.insert_arithmetic_tiny_lookup(2, &arith_mem);

        // core row1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_dest_offset_row,
            &stack_offset_row,
            &stack_length_row,
        ]);

        // core row0
        let mut core_row_0 = ExecutionState::MCOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let length_inv = U256::from_little_endian(
            F::from(length.low_u64())
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );

        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            length_inv
        );

        // 根据栈里的输入记录length和memory_size
        current_state.length_in_stack = Some(length.as_u64());
        current_state.new_memory_size = Some(offset_bound.as_u64());

        // 在外部gen_witness时，我们将current.gas_left预处理为trace.gas - trace.gas_cost
        // 但是某些复杂的gas计算里，真正的gas计算是在执行状态的最后一步，此时我们需要保证这里的gas_left与
        // 上一个状态的gas_left一致，也即trace.gas。
        // 在生成core_row_0时我们没有改变current.gas_left是因为这样做会导致重复的代码。
        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());

        // 固定的预分配位置
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            offset_bound
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            current_state.memory_chunk_prev.into()
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX],
            length.into()
        );

        let mut state_rows_final = vec![stack_dest_offset_row, stack_offset_row, stack_length_row];
        state_rows_final.extend(state_rows);

        // put rows into the Witness object
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows_final,
            copy: copy_rows,
            arithmetic: arith_mem,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MCopyGadget {
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
    fn test_mcopy() {
        let (dest_offset, offset, length) = (32, 0, 10);
        let stack = Stack::from_slice(&[length.into(), offset.into(), dest_offset.into()]);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer,
            memory_chunk_prev: ((dest_offset + length - 1) / 32) + 1,
            memory_chunk: ((dest_offset + length - 1) / 32) + 1,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::MCOPY, stack);
        let memory_size = 10 + 32;
        trace.memory.0 = vec![0; memory_size];
        for i in 0..memory_size {
            trace.memory.0[i] = (i % u8::MAX as usize) as u8
        }

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::MEMORY_GAS.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
