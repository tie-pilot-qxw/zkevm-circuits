use crate::arithmetic_circuit::operation;
use crate::constant::{
    GAS_LEFT_IDX, LENGTH_IDX, MEMORY_CHUNK_PREV_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY,
};
use crate::execution::ExecutionState::MEMORY_GAS;
use crate::execution::{
    memory_gas, AuxiliaryOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::state::CallContextTag;
use crate::witness::{arithmetic, assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::CoreSinglePurposeOutcome;

const NUM_ROW: usize = 4;
const STATE_STAMP_DELTA: u64 = 5;
const STACK_POINTER_DELTA: i32 = -3;
const PC_DELTA: u64 = 1;
const LEN_LO_INV_COL_IDX: usize = 9;

/// ReturnDataCopy Execution State layout is as follows
/// where RSSTATE means return data size state table lookup
/// STATE means state table lookup(call_context read returndata_call_id, stack pop dst_offset, stack_pop offset, stack_pop length),
/// ARITH(9) means return data size - (offset+length)
/// ARITH(5) means memory expansion
/// LI(1) means length lo inv
/// Copy(CP) means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// new_memory_size is `length + offset`
/// memory_chunk_prev is the previous memory chunk
/// length is the opcode input parameter
/// +---+-------+-----------------------+-------+-------------------------------------------------------+
/// |cnt| 8 col |           8 col       | 8 col |  8col                                                 |
/// +---+-------+-----------------------+-------+-------------------------------------------------------+
/// | 3 |RSSTATE|                       |       |                                                       |
/// | 2 |ARITH(9) |LI(1)|                        |ARITH(5)                                              |
/// | 1 | STATE |        STATE          | STATE | STATE                                                 |
/// | 0 |       DYNA_SELECTOR             | AUX | new_memory_size(26) |memory_chunk_prev(27)|length(28) |
/// +---+-------+-----------------------+-------+-------------------------------------------------------+
pub struct ReturndatacopyGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ReturndatacopyGadget<F>
{
    fn name(&self) -> &'static str {
        "RETURNDATACOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::RETURNDATACOPY
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
        let copy_entry = config.get_copy_lookup(meta, 1);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        // get length arithmetic lookup
        let length_arithmetic_entry = config.get_arithmetic_lookup(meta, 0);
        let (length_arithmetic_tag, length_arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, length_arithmetic_entry.clone());

        let mut constraints = vec![];

        // index0: dst_offset, index1: offset, index2: copy_lookup_len,
        let mut top2_stamp = 0.expr();
        let mut state_values = vec![];
        for i in 0..4 {
            let state_entry = config.get_state_lookup(meta, i);
            if i == 0 {
                constraints.append(&mut config.get_returndata_call_id_constraints(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                ));
            } else {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    (-1 * (i - 1) as i32).expr(),
                    false,
                ));
            }
            let (_, stamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);

            constraints.extend([(format!("value_high_{} = 0", i), value_hi.expr())]);

            state_values.push(value_lo);
            if i == 3 {
                top2_stamp = stamp;
            }
        }
        // get return data size lookup
        let returndata_size_entry = config.get_returndata_size_state_lookup(meta);
        constraints.append(&mut config.get_call_context_constraints(
            meta,
            returndata_size_entry.clone(),
            4,
            NUM_ROW,
            false,
            (CallContextTag::ReturnDataSize as u8).expr(),
            state_values[0].clone(),
        ));
        let (_, _, returndata_size_hi, returndata_size_lo, _, _, _, _) =
            extract_lookup_expression!(state, returndata_size_entry);

        let length = state_values[3].clone();
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation(-2));
        let is_zero_len = SimpleIsZero::new(&length, &len_lo_inv, String::from("length_lo"));
        constraints.append(&mut is_zero_len.get_constraints());

        let returndata_call_id = state_values[0].clone();
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Returndata,
            returndata_call_id.clone(),
            state_values[2].clone(),
            top2_stamp.clone() + 2.expr(),
            copy::Tag::Memory,
            call_id,
            state_values[1].clone(),
            top2_stamp + length.clone() + 2.expr(),
            None,
            length.clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));

        constraints.extend([(
            "opcode is RETURNDATACOPY".into(),
            opcode - OpcodeId::RETURNDATACOPY.expr(),
        )]);
        // pc, call_id,code_addr,tx_idx constraints
        constraints.append(&mut config.get_next_single_purpose_constraints(
            meta,
            // 后移pc至memory copier gas
            CoreSinglePurposeOutcome::default(),
        ));

        // constraint return data size hi must be 0
        constraints.push(("returndata_size_hi = 0".into(), returndata_size_hi.clone()));

        // constraints value from length arithmetic lookup
        constraints.extend([
            (
                "offset = state_values[2]".into(),
                length_arithmetic_operands_full[0].clone() - state_values[2].clone(),
            ),
            (
                "length = state_values[3]".into(),
                length_arithmetic_operands_full[1].clone() - length.clone(),
            ),
            (
                "size = returndata_size_lo".into(),
                length_arithmetic_operands_full[2].clone() - returndata_size_lo.clone(),
            ),
            (
                "offset + length <= returnda_size".into(),
                length_arithmetic_operands_full[3].clone(),
            ),
        ]);

        // Add constraints for length arithmetic tag.
        constraints.push((
            "arithmetic tag".into(),
            length_arithmetic_tag.clone() - (arithmetic::Tag::Length as u8).expr(),
        ));

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (mem_tag, [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 5));

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - is_zero_len.expr()) in state lookup"
                .into(),
            (state_values[1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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
            mem_tag.clone() - (arithmetic::Tag::MemoryExpansion as u8).expr(),
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
            (state_values[1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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

        // code_copy will increase the stamp automatically
        // state_stamp_delta = STATE_STAMP_DELTA + copy_lookup_len(copied code)
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + (len.clone() * 2.expr()),
            ),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
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
        let call_context_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        let returndata_size_lookup =
            query_expression(meta, |meta| config.get_returndata_size_state_lookup(meta));
        let code_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 1));

        let arith_length_lookup =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        let arith_mem_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        vec![
            (
                "state lookup, call_context read returndata_call_id".into(),
                call_context_lookup,
            ),
            ("state lookup, stack pop dst_offset".into(), stack_lookup_0),
            (
                "state lookup, stack pop lookup offset".into(),
                stack_lookup_1,
            ),
            (
                "state lookup, stack pop lookup length".into(),
                stack_lookup_2,
            ),
            ("returndata copy lookup".into(), code_copy_lookup),
            ("arithmetic length lookup".into(), arith_length_lookup),
            ("arithmetic tiny lookup".into(), arith_mem_lookup),
            (
                "return data size lookup at Rotation(-3)".into(),
                returndata_size_lookup,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::RETURNDATACOPY);
        //get call_context read returndata_call_id row
        let call_context_read = current_state.get_returndata_call_id_row(false);
        // get dstOffset、offset、length from stack top
        let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);
        let (call_context_returndata_size, returndata_size) =
            current_state.get_current_returndata_size_read_row();
        let mut core_row_3 = current_state.get_core_row_without_versatile(&trace, 3);
        // insert return data size in cnt = 3 row
        core_row_3.insert_returndata_size_state_lookup(&call_context_returndata_size);
        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // generate copy rows and state rows(type: memory)
        let (copy_rows, copy_state_rows) =
            current_state.get_return_data_copy_rows::<F>(dst_offset, offset, length);
        // insert lookUp: Core ---> Copy
        if length == 0.into() {
            core_row_2.insert_copy_lookup(
                1,
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
            core_row_2.insert_copy_lookup(1, &copy_rows[0]);
        }

        let len_lo = F::from_u128(length.low_u128());
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        //len_lo_inv
        assign_or_panic!(core_row_2[LEN_LO_INV_COL_IDX], len_lo_inv);

        // 若不满足,应该在trace中有ErrReturnDataOutOfBounds
        assert!(offset + length <= returndata_size);

        let (mut arith_length, arith_length_result) =
            operation::length::gen_witness::<F>(vec![offset, length, returndata_size]);
        assert_eq!(arith_length_result[0], U256::zero());

        core_row_2.insert_arithmetic_lookup(0, &arith_length);

        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            dst_offset + length
        };
        let (mut arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &call_context_read,
            &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let mut core_row_0 = ExecutionState::RETURNDATACOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
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

        let mut state_rows = vec![
            call_context_read,
            stack_pop_dst_offset,
            stack_pop_offset,
            stack_pop_length,
            call_context_returndata_size,
        ];
        state_rows.extend(copy_state_rows);

        let mut arithmetic_rows = vec![];
        arithmetic_rows.append(&mut arith_length);
        arithmetic_rows.append(&mut arith_mem);

        Witness {
            core: vec![core_row_3, core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ReturndatacopyGadget {
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
        //add WitnessExecHelper test return_data 数据
        let stack = Stack::from_slice(&[0.into(), 0.into(), 2.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.returndata_call_id = 0xff;
        current_state.return_data.insert(
            current_state.returndata_call_id,
            [0x12, 0x13, 0x14, 0x15, 0x16].to_vec(),
        );
        current_state.returndata_size = current_state.return_data
            [&current_state.returndata_call_id]
            .len()
            .into();
        current_state.gas_left = 100;

        let trace = prepare_trace_step!(0, OpcodeId::RETURNDATACOPY, stack);
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
        prover.assert_satisfied_par();
    }
}
