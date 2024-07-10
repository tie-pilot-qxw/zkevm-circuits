use crate::arithmetic_circuit::operation;
use crate::execution::{
    memory_gas, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};

use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{arithmetic, assign_or_panic, copy, public, Witness, WitnessExecHelper};

use crate::constant::{
    BLOCK_IDX_LEFT_SHIFT_NUM, GAS_LEFT_IDX, LENGTH_IDX, MEMORY_CHUNK_PREV_IDX,
    NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY,
};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::LogTag;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// LogBytes Execution State layout is as follows
/// where COPY means copy table lookup , 9 cols
/// PUBLIC means public table lookup 6 cols, origin from col 26
/// STATE means state table lookup,
/// LO_INV means length's inv , 1 col, located at col 24
/// ARITH means memory expansion arithmatic lookup
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+---------+---------+
/// |cnt| 8 col | 8 col |  8 col  |  8col   |
/// +---+-------+-------+---------+---------+
/// | 2 | Copy(9) | ARITH(5)    | PUBLIC(6) |
/// | 1 | STATE | STATE | notUsed | LO_INV(1 col) |
/// | 0 | DYNA_SELECTOR | AUX               |
/// +---+-------+-------+---------+---------+
///

pub(crate) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = -2;
const LEN_LO_INV_COL_IDX: usize = 24;

pub struct LogBytesGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LogBytesGadget<F>
{
    fn name(&self) -> &'static str {
        "LOG_BYTES"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LOG_BYTES
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        let block_tx_idx =
            (block_idx.clone() * (1u64 << BLOCK_IDX_LEFT_SHIFT_NUM).expr()) + tx_idx.clone();

        let Auxiliary { log_stamp, .. } = config.get_auxiliary();
        let log_stamp = meta.query_advice(log_stamp, Rotation(NUM_ROW as i32 * -1));

        // build constraints ---
        // append auxiliary constraints
        let copy_entry = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        let mut constraints = vec![];

        // append stack constraints
        let mut stack_pop_values = vec![];
        let mut stamp_start = 0.expr();
        for i in 0..2 {
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
            stack_pop_values.push(value_hi); // 0
            stack_pop_values.push(value_lo);
            if i == 1 {
                stamp_start = stamp;
            }
        }

        // append core single purpose constraints
        let delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // append log_bytes constraints
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation::prev());
        let is_zero_len =
            SimpleIsZero::new(&stack_pop_values[3], &len_lo_inv, String::from("length_lo"));

        constraints.append(&mut is_zero_len.get_constraints());
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Memory,
            call_id,
            stack_pop_values[1].clone(),
            stamp_start + 1.expr(),
            copy::Tag::PublicLog,
            block_tx_idx.clone(),
            0.expr(),          // index of PublicLog
            log_stamp.clone(), // log_stamp from Auxiliary
            None,
            stack_pop_values[3].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));

        // append addrWithXLog constraints
        let (
            public_tag,
            public_block_tx_idx,
            public_values, // public_log_stamp, public_log_tag, public_log_addr_hi, public_log_addr_lo
        ) = extract_lookup_expression!(public, config.get_public_lookup(meta, 0));

        constraints.extend([
            (
                "public tag is tx_log".into(),
                public_tag - (public::Tag::TxLog as u8).expr(),
            ),
            (
                "public block_tx_idx = (block_idx << BLOCK_IDX_LEFT_SHIFT_NUM) + tx_idx".into(),
                public_block_tx_idx - block_tx_idx.clone(),
            ),
            (
                "public log_stamp is correct".into(),
                public_values[0].clone() - log_stamp,
            ),
            (
                "public log tag is DataSize".into(),
                public_values[1].clone() - (LogTag::DataSize as u8).expr(),
            ),
            ("public values[2] is 0".into(), public_values[2].clone()),
            (
                "public data_len is length".into(),
                public_values[3].clone() - len.clone(),
            ),
        ]);

        // next state should be log_topic_num_addr.
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
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 2));

        let length = stack_pop_values[3].clone();

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - is_zero_len.expr()) in state lookup"
                .into(),
            (stack_pop_values[1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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
            (stack_pop_values[1].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr() + len.clone()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));

        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 2));

        vec![
            (
                "state lookup, stack pop lookup offset".into(),
                stack_lookup_0,
            ),
            (
                "state lookup, stack pop lookup length".into(),
                stack_lookup_1,
            ),
            ("code copy lookup".into(), copy_lookup),
            ("public lookup".into(), public_lookup),
            ("arithmetic tiny lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get offset、length from stack top
        // let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate core rows
        // core_row_2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows) =
            current_state.get_log_bytes_rows::<F>(trace, offset, length);

        // insert lookUp: Core ---> Copy
        if length.is_zero() {
            core_row_2.insert_copy_lookup(0, &Default::default());
        } else {
            core_row_2.insert_copy_lookup(0, &copy_rows[0]);
        }

        // write addrWithXLog to core_row_2.vers_26 ~ vers_31
        // insert lookUp: Core ----> addrWithXLog
        let public_row = current_state.get_public_log_data_size_row(length);
        core_row_2.insert_public_lookup(0, &public_row);

        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            offset + length
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(2, &arith_mem);

        // core_row_1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        let len_lo = F::from_u128(length.as_u128());
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_1[LEN_LO_INV_COL_IDX], len_lo_inv);

        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            // &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        // core_row_0
        let mut core_row_0 = ExecutionState::LOG_BYTES.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
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
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX],
            length.into()
        );

        let mut state_rows = vec![stack_pop_offset, stack_pop_length];
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
    Box::new(LogBytesGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use crate::witness::WitnessExecHelper;
    generate_execution_gadget_test_circuit!();
    fn assign_and_constraint(opcode: OpcodeId, stack: Stack) {
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x0;
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            log_stamp,
            memory_chunk: 1,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, opcode, stack);
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
            // row.pc = 0.into();
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied();
    }
    #[test]
    fn test_log_bytes_log0() {
        let opcode = OpcodeId::LOG0;
        let stack = Stack::from_slice(&[0x4.into(), 0x1.into()]);
        assign_and_constraint(opcode, stack)
    }

    #[test]
    fn test_log_bytes_log1() {
        let opcode = OpcodeId::LOG1;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(opcode, stack)
    }
}
