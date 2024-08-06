// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;
use crate::constant::{
    GAS_LEFT_IDX, MEMORY_CHUNK_PREV_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY,
};
use crate::execution::{
    memory_gas, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
};
use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, bitwise, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;

const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -2;
const PC_DELTA: u64 = 1;
const BYTE_MAX: u8 = 0xff;

/// MSTORE8 gadget:
/// MSTORE8 algorithm overview：
///    1.pop the two elements on top of the stack
///       stack_pop_0: offset, stack_top1: value
///    2.calculate value & 0xff and write it to memory[offset]
/// Table layout:
///     BITWISE_LO: Bitwise low 16 byte lookup, src: Core circuit, target: Bitwise circuit table, 5 columns
///     STATE0:  State lookup(stack_pop_0), src: Core circuit, target: State circuit table, 8 columns
///     STATE1:  State lookup(stack_pop_1), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  stack lookup(memory_write), src: Core circuit, target: State circuit table, 8 columns
///     ARITH5:  Arithmetic memory expansion lookup, 5 columns
///     OFFSET_BOUND: `offset + 1`
///     MEMORY_CHUNK_PREV: the previous memory chunk
/// +---+-------+--------+--------+----------+-+----------------+-----------------------+
/// |cnt| 8 col | 8 col  | 8 col  | 8 col    |                  |                       |
/// +---+-------+--------+--------+----------+------------------+-----------------------+
/// | 2 | NOTUSED(10)| BITWISE_LO(5)|ARITH(5)|                  |                       |
/// | 1 | STATE1| STATE2 | STATE3 |          |                  |                       |
/// | 0 | DYNA_SELECTOR         | AUX        | OFFSET_BOUND(26) | MEMORY_CHUNK_PREV(27) |
/// +---+-------+--------+--------+----------+-+----------------+-----------------------+
///
/// NOTE: here we only need bitwise_lo, because proving result == value & 0xff is equivalent to proving result == value_lo & 0xff.
pub struct MStore8Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MStore8Gadget<F>
{
    fn name(&self) -> &'static str {
        "MSTORE8"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MSTORE8
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
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        let mut constraints = vec![];

        // append stack constraints and memory constraints
        let mut operands: Vec<[Expression<F>; 2]> = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            if i <= 1 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    -i.expr(),
                    false,
                ));
            } else {
                constraints.append(&mut config.get_memory_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    operands[0][1].clone(), // pointer_lo of memory write should be equal to value_lo (offset_lo) of stack_pop_0
                    true,
                ));
            }

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // offset hi and value hi of memory-type state lookup should be zero
        constraints.extend([
            ("offset_hi == 0".into(), operands[0][0].clone()),
            ("memory write value hi ==0".into(), operands[2][0].clone()),
        ]);
        // append bitwise constraints
        let bitwise_entry = config.get_bitwise_lookup(meta, 0);
        constraints.append(&mut config.get_bitwise_constraints(
            meta,
            bitwise_entry,
            (bitwise::Tag::And as u8).expr(),
            operands[1][1].clone(), // acc_0 should be equal to value_lo of stack_pop_1
            BYTE_MAX.expr(),
            Some(operands[2][1].clone()), // acc_2 (the result of value_lo & 0xff) should be equal to memory write value
            None,
        ));
        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            opcode.clone() - OpcodeId::MSTORE8.as_u8().expr(),
        )]);

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (tag, [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 5));
        // constraint for arithmetic operand
        constraints.push((
            "offset in arithmetic = in state lookup + 1".into(),
            offset_bound.clone() - operands[0][1].clone() - 1.expr(),
        ));
        constraints.push((
            "memory_chunk_prev in arithmetic = in auxiliary".into(),
            memory_chunk_prev.clone()
                - meta.query_advice(
                    config.get_auxiliary().memory_chunk,
                    Rotation(-1 * NUM_ROW as i32).clone(),
                ),
        ));

        // Add constraints for arithmetic tag.
        constraints.push((
            "arithmetic tag".into(),
            tag.clone() - (arithmetic::Tag::MemoryExpansion as u8).expr(),
        ));

        // next state constraints
        let memory_size_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation::cur(),
        );
        constraints.push((
            "memory_size_for_next == in state lookup + 1".into(),
            (operands[0][1].clone() + 1.expr()) - memory_size_for_next.clone(),
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

        let memory_chunk_to = expansion_tag.clone() * access_memory_size.clone()
            + (1.expr() - expansion_tag.clone()) * memory_chunk_prev;

        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        // pc 后移至pureMemoryGas
        let core_single_delta = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        // next state is MEMORY_GAS
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::MEMORY_GAS, memory_gas::NUM_ROW, None)],
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
        let memory_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let bitwise_lookup = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 0));
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        vec![
            ("stack lookup 0".into(), stack_lookup_0),
            ("stack lookup 1".into(), stack_lookup_1),
            ("memory lookup".into(), memory_lookup),
            ("bitwise lookup".into(), bitwise_lookup),
            ("arithmetic lookup".into(), arithmetic_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::MSTORE8);
        //get stack_pop rows and values
        let (stack_pop_0, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, value) = current_state.get_pop_stack_row_value(&trace);

        let value_lo = value.low_u128();
        // get bitwise rows
        let bitwise_rows =
            bitwise::Row::from_operation::<F>(bitwise::Tag::And, value_lo, BYTE_MAX.into());
        // get memory write value and memory write row
        // we don't need to consider whether offset overflows because Ethereum has checked that.
        // reference : https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L43
        let acc_2 = bitwise_rows.last().unwrap().acc_2;
        let memory_write_row = current_state.get_memory_write_row(offset, acc_2.as_usize() as u8);

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // insert lookUp: Core ---> Bitwise
        core_row_2.insert_bitwise_lookups(0, &bitwise_rows.last().unwrap());

        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset + U256::one(), memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &memory_write_row]);

        let mut core_row_0 = ExecutionState::MSTORE8.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            current_state.returndata_size
        );

        // 根据栈里的输入记录length和memory_size
        let offset_bound = offset + U256::one();
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

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, memory_write_row],
            bitwise: bitwise_rows,
            arithmetic: arith_mem,

            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MStore8Gadget {
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
    fn assign_and_constraint_mstore8() {
        let mut value_vec: [u8; 32] = Default::default();
        for i in 0..32 {
            value_vec[i] = (i + 1) as u8;
        }
        let value = U256::from_big_endian(&value_vec);

        let stack = Stack::from_slice(&[value, 0xffff.into()]);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            memory_chunk: 0x800,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, OpcodeId::MSTORE8, stack);

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
