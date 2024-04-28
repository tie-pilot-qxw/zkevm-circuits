use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const PC_DELTA: usize = 1;
const STATE_STAMP_DELTA: usize = 3;
const STACK_POINTER_DELTA: i32 = -3;
const LEN_LO_INV_COL_IDX: usize = 24;

/// CALLDATACOPY copy message data from calldata to memory in EVM.
///
/// CALLDATACOPY Execution State layout is as follows
/// where COPY means copy table lookup (dst_offset, src_offset, length),
/// LENGTH means retrieve data length from calldata,
/// ARITH means memory expansion arithmatic lookup
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY   |       |       | ARITH(5)|
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct CalldatacopyGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CalldatacopyGadget<F>
{
    fn name(&self) -> &'static str {
        "CALLDATACOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALLDATACOPY
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
        let opcode_advice = meta.query_advice(config.opcode, Rotation::cur());
        // create custom gate constraints
        let copy_entry = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        let mut constraints = vec![];

        let mut stack_pop_values = vec![];
        // calldatacopy has three operand.
        for i in 0..3 {
            let state_entry = config.get_state_lookup(meta, i);
            // 对core电路的3个state状态进行约束
            constraints.append(&mut config.get_stack_constraints(
                meta,
                state_entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, state_entry);
            stack_pop_values.push(value_lo);
            constraints.extend([(format!("value_high_{} = 0", i), value_hi.expr())])
        }

        let length = stack_pop_values[2].clone();
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation::prev());
        let is_zero_len = SimpleIsZero::new(&length, &len_lo_inv, String::from("length_lo"));
        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 2));
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        constraints.append(&mut is_zero_len.get_constraints());
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Calldata,
            call_id.clone(),
            stack_pop_values[1].clone(),
            // +1.expr() after state row is generated, the stamp+=1 affected, thus subsequent copy_row start at stamp+=1.
            stamp.clone() + 1.expr(),
            copy::Tag::Memory,
            call_id,
            stack_pop_values[0].clone(),
            stamp + stack_pop_values[2].clone() + 1.expr(),
            None,
            stack_pop_values[2].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));
        constraints.extend([(
            "opcode".into(),
            opcode_advice - OpcodeId::CALLDATACOPY.as_u64().expr(),
        )]);

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (tag, [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 5));

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - is_zero_len.expr()) in state lookup"
                .into(),
            (stack_pop_values[0].clone() + length.clone()) * (1.expr() - is_zero_len.expr())
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

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                // 因为copy的数据写了2份，所以需要len*2，同时记录了三个state状态
                STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            ),
            // 弹出了三个操作数
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            ..Default::default()
        };
        // 添加辅助列的约束，约束上下相邻指令的状态
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        // 约束pc、tx_id等状态
        let delta = CoreSinglePurposeOutcome {
            // 因为pc向后移动1，该指令下同一笔交易中其它状态不变
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // 从core电路中读取3个操作数的state 状态，与state 电路进行lookup约束
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        // 从core电路中读取copy 的状态，与copy电路进行lookup约束
        let calldata_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        vec![
            (
                "state lookup, stack top 0 dst_offset".into(),
                stack_lookup_0,
            ),
            (
                "state lookup, stack top 1 src_offset".into(),
                stack_lookup_1,
            ),
            ("state lookup, stack top2 length".into(), stack_lookup_2),
            ("copy lookup".into(), calldata_copy_lookup),
            ("arithmetic tiny lookup".into(), arithmetic_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get three operand from stack
        // [dast_offset, calldata_offset, length]
        let (stack_pop_0, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, calldata_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_2, length) = current_state.get_pop_stack_row_value(&trace);

        // get copydata and state rows from calldata
        // state rows 对copy的length字节记录两次，第一次为 calldata区域的读取
        // 第二次为memory区域的写入
        let (copy_rows, mut state_rows) =
            current_state.get_calldata_copy_rows::<F>(dst_offset, calldata_offset, length);

        // get three core circuit and fill content to them
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        if length.is_zero() {
            core_row_2.insert_copy_lookup(0, &copy::Row::default());
        } else {
            core_row_2.insert_copy_lookup(0, copy_rows.get(0).unwrap());
        }

        // core电路写入三个操作数的state 状态
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_pop_2]);
        // 记录copy数据字节大小的倒数，在约束逻辑区分长度为0和非0情况
        let len_lo = F::from_u128(length.low_u128());
        let lenlo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_1[LEN_LO_INV_COL_IDX], lenlo_inv);

        // 插入执行指令的flag
        let core_row_0 = ExecutionState::CALLDATACOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            dst_offset + length
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);

        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        // generate witness for coredataload instruct
        state_rows.extend(vec![stack_pop_0, stack_pop_1, stack_pop_2]);
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
    Box::new(CalldatacopyGadget {
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
    fn copylength_less_or_equal_calldata() {
        //[length, src_offset, dst_offset]
        let stack = Stack::from_slice(&[0x01.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            memory_chunk: 1,
            memory_chunk_prev: 0,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        run_prover(stack, current_state, "copylength_le_calldata")
    }

    #[test]
    fn copylength_great_calldata() {
        let stack = Stack::from_slice(&[0x20.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            memory_chunk: 2,
            memory_chunk_prev: 0,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        run_prover(stack, current_state, "copylength_gt_calldata");
    }

    #[test]
    fn copylength_equal_0() {
        let stack = Stack::from_slice(&[0x00.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        run_prover(stack, current_state, "copylength_eq_0");
    }

    fn run_prover(stack: Stack, mut current_state: WitnessExecHelper, _file_name: &str) {
        let stack_pointer = stack.0.len();
        let trace = prepare_trace_step!(0, OpcodeId::CALLDATACOPY, stack);
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
        prover.assert_satisfied_par();
    }
}
