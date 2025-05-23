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
    memory_gas, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{arithmetic, assign_or_panic, copy, state, Witness, WitnessExecHelper};

use crate::util::{query_expression, ExpressionOutcome};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// ReturnRevert Execution State layout is as follows
/// where COPY means copy table lookup , 11 cols
/// STATE means state table lookup,
/// ARITH means memory expansion arithmatic lookup
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// OFFSET_BOUND is `length_not_zero * (offset + length)`
/// MEMORY_CHUNK_PREV is the previous memory chunk
/// +---+-------+-------+---------+---------+-----------+-------------------+-----------------------+
/// |cnt| 8 col | 8 col |  8 col  |  8col   |           |                   |                       |
/// +---+-------+-------+---------+---------+-----------+-------------------+-----------------------+
/// | 2 | Copy(11) | LEN_LO_INV(1)| ARITH(5)|           |                   |                       |
/// | 1 | STATE | STATE | STATE   | STATE   |           |                   |                       |
/// | 0 | DYNA_SELECTOR      | AUX  | ReturnDataSize(25)|  OFFSET_BOUND(26) | MEMORY_CHUNK_PREV(27) |
/// +---+-------+-------+---------+---------+-----------+-------------------+-----------------------+
///

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;
const STACK_POINTER_DELTA: i32 = -2;
const LEN_LO_INV_COL_IDX: usize = 11;

pub struct ReturnRevertGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ReturnRevertGadget<F>
{
    fn name(&self) -> &'static str {
        "RETURN_REVERT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::RETURN_REVERT
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let mut constraints = vec![];

        // build constraints ---
        // append auxiliary constraints
        let copy_entry = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        // append stack constraints
        let mut operands = vec![];
        for i in 0..4 {
            let state_entry = config.get_state_lookup(meta, i);
            if i < 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    (-1 * i as i32).expr(),
                    false,
                ));
            } else {
                constraints.append(
                    &mut config.get_call_context_constraints(
                        meta,
                        state_entry.clone(),
                        i,
                        NUM_ROW,
                        true,
                        if i == 2 {
                            state::CallContextTag::ReturnDataCallId as u8
                        } else {
                            state::CallContextTag::ReturnDataSize as u8
                        }
                        .expr(),
                        if i == 2 { 0.expr() } else { call_id.clone() }, // when CallContextTag is ReturnDataCallId, the call_id is 0.
                    ),
                );
            }
            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);
            operands.push([value_hi, value_lo]);
        }

        constraints.extend([
            ("offset hi == 0".into(), operands[0][0].clone()),
            ("len hi == 0".into(), operands[1][0].clone()),
            ("returndata_call_id hi == 0".into(), operands[2][0].clone()),
            (
                "returndata_call_id lo == call_id".into(),
                operands[2][1].clone() - call_id.clone(),
            ),
            (
                "returndata_size hi == len hi".into(),
                operands[3][0].clone() - operands[1][0].clone(),
            ),
            (
                "returndata_size lo == len lo".into(),
                operands[3][1].clone() - operands[1][1].clone(),
            ),
        ]);

        let returndata_size_record = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        constraints.extend([(
            "returndata_size_record correct".into(),
            returndata_size_record - operands[3][1].clone(),
        )]);

        // append core single purpose constraints
        let delta = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // append return&revert constraints
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation(-2));
        let is_zero_len =
            SimpleIsZero::new(&operands[1][1], &len_lo_inv, String::from("length_lo"));

        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 3));

        constraints.append(&mut is_zero_len.get_constraints());
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Memory,
            call_id.clone(),
            operands[0][1].clone(),
            stamp.clone() + 1.expr(),
            copy::Tag::Returndata,
            call_id,
            0.expr(),
            stamp.clone() + operands[1][1].clone() + 1.expr(),
            None,
            operands[1][1].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));

        // extend opcode and pc constraints
        constraints.extend([(
            "opcode is RETURN or REVERT".into(),
            (opcode.clone() - OpcodeId::RETURN.expr()) * (opcode - OpcodeId::REVERT.expr()),
        )]);
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

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (tag, [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 5));

        let length = operands[1][1].clone();

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - is_zero_len.expr()) in state lookup"
                .into(),
            (operands[0][1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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
            "memory_size_for_next ==  (mem_off + length) * (1 - is_zero_len.expr()) in state lookup".into(),
            (operands[0][1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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

        let memory_chunk_to = expansion_tag.clone() * access_memory_size.clone()
            + (1.expr() - expansion_tag.clone()) * memory_chunk_prev;

        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            ),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        vec![
            (
                "state lookup, stack pop lookup offset".into(),
                stack_lookup_0,
            ),
            (
                "state lookup, stack pop lookup length".into(),
                stack_lookup_1,
            ),
            (
                "state lookup, call_context write returndata_call_id".into(),
                call_context_lookup_0,
            ),
            (
                "state lookup, call_context write returndata_size".into(),
                call_context_lookup_1,
            ),
            ("code copy lookup".into(), copy_lookup),
            ("arithmetic tiny lookup".into(), arithmetic_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get offset、length from stack top
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        //update returndata_call_id, returndata_call_size, returndata and return_success
        current_state.returndata_call_id = current_state.call_id.clone();
        current_state.returndata_size = length;
        // it's guaranteed by Ethereum memory usage limitation that offset.as_usize() and length.as_usize() won't panic.
        let returndata = trace
            .memory
            .read_chunk(offset.as_usize().into(), length.as_usize().into());
        current_state
            .return_data
            .insert(current_state.returndata_call_id, returndata);
        current_state.return_success = true;

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

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows) =
            current_state.get_return_revert_rows::<F>(trace, offset, length);
        // insert lookUp: Core ---> Copy
        if length.is_zero() {
            core_row_2.insert_copy_lookup(0, &Default::default());
        } else {
            core_row_2.insert_copy_lookup(0, &copy_rows[0]);
        }

        let len_lo = F::from_u128(length.as_u128());
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_2[LEN_LO_INV_COL_IDX], len_lo_inv);

        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            offset + length
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_pop_offset,
            &stack_pop_length,
            &call_context_write_row_0,
            &call_context_write_row_1,
        ]);

        let mut core_row_0 = ExecutionState::RETURN_REVERT.into_exec_state_core_row(
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

        let mut state_rows = vec![
            stack_pop_offset,
            stack_pop_length,
            call_context_write_row_0,
            call_context_write_row_1,
        ];
        state_rows.extend(memory_state_rows);

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
            arithmetic: arith_mem,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ReturnRevertGadget {
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
        let stack = Stack::from_slice(&[0x05.into(), 0x00.into()]); // len=5, offset=0
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            memory_chunk_prev: 0,
            memory_chunk: 1,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::RETURN, stack);
        trace.memory.push("hello");

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
            row.pc = 0.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
