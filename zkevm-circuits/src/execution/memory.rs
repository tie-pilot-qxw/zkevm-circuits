use crate::arithmetic_circuit::operation;
use crate::execution::{
    memory_gas, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};

use crate::constant::{
    GAS_LEFT_IDX, MEMORY_CHUNK_PREV_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;

const STATE_STAMP_DELTA: u64 = 34;
const STACK_POINTER_DELTA_MLOAD: i32 = 0;
const STACK_POINTER_DELTA_MSTORE: i32 = -2;
const PC_DELTA: u64 = 1;

/// Memory is a combination of Mload and Mstore.
/// Algorithm overview:
/// MLOAD:
///     1. get offset from stack
///     2. get value = memory[offset:offset+32]
///     3. write value to stack
/// MSTORE:
///     1. get offset and value from stack
///     2. write value to memory[offset:offset+32]
/// Table layout:
///     STATE1:  State lookup(stack pop offset), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack pop/push value), src: Core circuit, target: State circuit table, 8 columns
///     COPY1:   Copy lookup(copy of high 16 bytes from/to memory), src:Core circuit, target:Copy circuit table, 11 columns
///     COPY2:   Copy lookup(copy of low 16 bytes from/to memory), src:Core circuit, target:Copy circuit table, 11 columns
///     ARITH:   memory expansion arithmatic lookup, 5 columns
///     OFFSET_BOUND: `offset + 32`
///     MEMORY_CHUNK_PREV: the previous memory chunk
///
/// +---+-------+--------+--------+-----------------------------------------------------+
/// |cnt| 8 col | 8 col  | 8 col  |                   8 col                             |
/// +---+-------+--------+--------+-----------------------------------------------------+
/// | 2 | COPY1(11) | COPY2(11) | ARITH(5)   |                  |                       |
/// | 1 | STATE1| STATE2 |                   |                  |                       |
/// | 0 | DYNA_SELECTOR         | AUX        | OFFSET_BOUND(26) | MEMORY_CHUNK_PREV(27) |
/// +---+-------+--------+--------+----------+------------------+-----------------------+
///
/// Note: acc of COPY1 and COPY2 are respectively value_hi and value_lo of STATE1
pub struct MemoryGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MemoryGadget<F>
{
    fn name(&self) -> &'static str {
        "MEMORY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MEMORY
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

        // append stack constraints
        let mut operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints_with_selector(
                meta,
                entry.clone(),
                if i == 0 { 0 } else { 33 }, // we let the stamps for memory read (32 in total) be between the stack read and the stack write for convenience, so the stamp for stack read and stack write is 0 and 33 respectively.
                NUM_ROW,
                0.expr(),
                i == 1,
                OpcodeId::MSTORE.as_u8().expr() - opcode.clone(), //enable the constraints when opcode == MLOAD
            ));
            constraints.append(&mut config.get_stack_constraints_with_selector(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                if i == 0 { 0 } else { -1 }.expr(),
                false,
                opcode.clone() - OpcodeId::MLOAD.as_u8().expr(), //enable the constraints when opcode == MSTORE
            ));

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraint for state_lookup's value
        constraints.extend([("offset_hi == 0".into(), operands[0][0].clone())]);
        // append copy constraints
        for i in 0..2 {
            let copy_entry = if i == 0 {
                config.get_copy_lookup(meta, 0)
            } else {
                config.get_copy_lookup(meta, 1)
            };

            let (_, stamp, ..) =
                extract_lookup_expression!(state, config.get_state_lookup(meta, 0));
            constraints.append(&mut config.get_copy_constraints_with_selector(
                copy::Tag::Memory,
                call_id.clone(),
                operands[0][1].clone() + 16.expr() * i.expr(),
                stamp.clone() + 1.expr() + 16.expr() * i.expr(), // the src_pointer and src_stamp of the second copy lookup has an increase of 16 compared to the first one
                copy::Tag::Null,
                0.expr(),
                0.expr(),
                0.expr(),
                Some(15.expr()), //the last cnt (16 - 1)
                16.expr(),
                0.expr(),
                Some(operands[1][i].clone()),
                OpcodeId::MSTORE.as_u8().expr() - opcode.clone(), //enable the constraints when opcode == MLOAD
                copy_entry.clone(),
            ));
            constraints.append(&mut config.get_copy_constraints_with_selector(
                copy::Tag::Null,
                0.expr(),
                0.expr(),
                0.expr(),
                copy::Tag::Memory,
                call_id.clone(),
                operands[0][1].clone() + 16.expr() * i.expr(),
                stamp.clone() + 2.expr() + 16.expr() * i.expr(), // the dst_pointer and dst_stamp of the second copy lookup has an increase of 16 compared to the first one
                Some(15.expr()),
                16.expr(),
                0.expr(),
                Some(operands[1][i].clone()),
                opcode.clone() - OpcodeId::MLOAD.as_u8().expr(), //enable the constraints when opcode == MSTORE
                copy_entry.clone(),
            ));
        }

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (tag, [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 4));

        // constraint for arithmetic operand
        constraints.push((
            "offset in arithmetic = in state lookup + 32".into(),
            offset_bound.clone() - operands[0][1].clone() - 32.expr(),
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
            "memory_size_for_next == in state lookup + 32".into(),
            (operands[0][1].clone() + 32.expr()) - memory_size_for_next.clone(),
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
            stack_pointer: ExpressionOutcome::Delta(
                STACK_POINTER_DELTA_MLOAD.expr()
                    * (OpcodeId::MSTORE.as_u8().expr() - opcode.clone())
                    + STACK_POINTER_DELTA_MSTORE.expr()
                        * (opcode.clone() - OpcodeId::MLOAD.as_u8().expr()),
            ), //the property OpcodeId::MSTORE - OpcodeId::MLOAD == 1 is used
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            (opcode.clone() - OpcodeId::MLOAD.expr()) * (opcode - OpcodeId::MSTORE.expr()),
        )]);
        // append core single purpose constraints
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
        let copy_lookup_0 = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let copy_lookup_1 = query_expression(meta, |meta| config.get_copy_lookup(meta, 1));

        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 4));

        vec![
            ("stack lookup 0".into(), stack_lookup_0),
            ("stack lookup 1".into(), stack_lookup_1),
            ("copy lookup 0".into(), copy_lookup_0),
            ("copy lookup 1".into(), copy_lookup_1),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::MLOAD || trace.op == OpcodeId::MSTORE);
        //generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        //generate stack pop/push rows, memory read/write rows and copy rows
        let (stack_row_0, offset) = current_state.get_pop_stack_row_value(&trace);

        let (stack_row_1, mut state_rows, copy_rows) = if trace.op == OpcodeId::MLOAD {
            let (copy_rows, state_rows) = current_state.get_mload_rows::<F>(trace, offset);

            let copy_row_0 = copy_rows.get(15).unwrap();
            let copy_row_1 = copy_rows.get(31).unwrap();
            // insert lookUp: Core ---> Copy
            core_row_2.insert_copy_lookup(0, copy_row_0);
            core_row_2.insert_copy_lookup(1, copy_row_1);
            let value = (copy_row_0.acc << 128) + copy_row_1.acc;
            let stack_row_1 = current_state.get_push_stack_row(trace, value);

            (stack_row_1, state_rows, copy_rows)
        } else {
            let (stack_row_1, value) = current_state.get_pop_stack_row_value(&trace);

            let (copy_rows, state_rows) = current_state.get_mstore_rows::<F>(offset, value);

            let copy_row_0 = copy_rows.get(15).unwrap();
            let copy_row_1 = copy_rows.get(31).unwrap();
            // insert lookUp: Core ---> Copy
            core_row_2.insert_copy_lookup(0, copy_row_0);
            core_row_2.insert_copy_lookup(1, copy_row_1);

            (stack_row_1, state_rows, copy_rows)
        };
        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let (arith_mem, result) = operation::memory_expansion::gen_witness(vec![
            offset + U256::from(32),
            memory_chunk_prev,
        ]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(4, &arith_mem);

        state_rows.extend(vec![stack_row_0.clone(), stack_row_1.clone()]);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&stack_row_0, &stack_row_1]);
        let mut core_row_0 = ExecutionState::MEMORY.into_exec_state_core_row(
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
        let offset_bound = offset + U256::from(32);
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
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            arithmetic: arith_mem,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MemoryGadget {
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
    fn assign_and_constraint_mload() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 32];
        let value = U256::from_big_endian(&value_vec);

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(value),
            memory_chunk_prev: ((0xffff + 31) / 32) + 1,
            memory_chunk: ((0xffff + 31) / 32) + 1,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::MLOAD, stack);
        trace.memory.0 = vec![0; 0x1001f];
        for i in 0..32 {
            trace.memory.0.insert(0xffff + i, value_vec[i]);
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
    #[test]
    fn assign_and_constraint_mstore() {
        let value = U256::from_big_endian(&[0x12; 32]);
        let stack = Stack::from_slice(&[value, 0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            memory_chunk_prev: ((0xffff + 31) / 32) + 1,
            memory_chunk: ((0xffff + 31) / 32) + 1,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, OpcodeId::MSTORE, stack);

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
