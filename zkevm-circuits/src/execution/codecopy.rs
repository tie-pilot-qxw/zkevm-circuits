use crate::arithmetic_circuit::operation;
use crate::constant::{GAS_LEFT_IDX, MAX_CODESIZE, NUM_AUXILIARY};
use crate::execution::ExecutionState::MEMORY_GAS;
use crate::execution::{
    memory_gas_cost, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, copy, public, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Overview:
///   CODECOPY is mainly used to copy bytecode of a specified length to Memory.
///   1. pop three elements from the top of the stack
///      stack_pop0: destOffset(for Memory, the starting copy length)
///      stack_pop1: offset(for Stack, the starting copy length)
///      stack_pop2: length(the length of the bytecode to be copied)
///   2. `memory[destOffset:destOffset+length] = address(this).code[offset:offset+length]`
///
/// There is a problem：
///    offset > len(Bytecode)
///    offset < len(Bytecode) && offset + length > len(Bytecode)
///   that is, the byte index to be copied exceeds the length of Bytecode，the byte of the specified index to be copied
/// does not exist
///
/// How to solve it?
///   divide copy into two parts, normal copy and zero copy:
///   normal copy: offset <= len(Bytecode) && offset+length <= len(Bytecode)
///   zero copy: mark copies that exceed the Bytecode length as invalid copies, using zero padding
///   use the Length operation method of the arithmetic circuit to calculate real_length, zero_length based on length, offset, len(Bytecode)
///
/// Table layout:
///     COPY: normal length Copy Lookup, src:Core circuit, target:Copy circuit table, 9 columns
///     ZEROCOPY: zero length Copy Lookup, src:Core circuit, target:Copy circuit table, 9 columns
///     LENGTH：arithmetic Length LookUp, src:Core circuit, target:Arithmetic circuit table, 9cols
///     PUB_CODE_SIZE：Codesize Lookup, src:Core circuit, target:Public circuit table, 6 cols
///     LENGTH_INV:  original codecopy length's multiplicative inverse
///     OVER_ARITH:  src offset overflow arithmetic lookup,src:Core circuit, target:Arithmetic circuit table, 5 cols
///     EXP_ARITH:  memory expansion arithmetic lookup,src:Core circuit, target:Arithmetic circuit table, 5 cols
///     new_memory_size is `length + offset`
///     memory_chunk_prev is the previous memory chunk
///     length is the opcode input parameter
/// +---+-------+-------+------------------------+--------------------------------------------------------+
/// |cnt| 8 col | 8 col |              8 col     | 8col                                                   |
/// +---+-------+-------+------------------------+--------------------------------------------------------+
/// | 3 |  LENGTH(9) |                              PUB_CODE_SIZE(6)                                      |
/// | 2 |  COPY   |    ZEROCOPY  |OVER_ARITH(5)|EXP_ARITH(5)                                              |
/// | 1 | STATE0| STATE1|        STATE2          |                                                        |
/// | 0 | DYNA_SELECTOR   | AUX |LENGTH_INV      |  new_memory_size(26) |memory_chunk_prev(27)|length(28) |
/// +---+-------+-------+------------------------+--------------------------------------------------------+

const NUM_ROW: usize = 4;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -3;
pub struct CodecopyGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CodecopyGadget<F>
{
    fn name(&self) -> &'static str {
        "CODECOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CODECOPY
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, memory_gas_cost::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let address = meta.query_advice(config.code_addr, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let copy_lookup_entry = config.get_copy_lookup(meta, 0);
        let copy_padding_lookup_entry = config.get_copy_lookup(meta, 1);
        let src_overflow_entry = config.get_arithmetic_tiny_lookup(meta, 4);
        let public_code_size_entry = config.get_public_lookup_with_rotation(meta, 0, Rotation(-3));
        let (
            arith_src_overflow_tag,
            [src_offset_hi, src_offset_lo, src_overflow, src_overflow_inv],
        ) = extract_lookup_expression!(arithmetic_tiny, src_overflow_entry);
        let length_entry = config.get_arithmetic_lookup_with_rotation(meta, 0, Rotation(-3));
        let (
            arith_length_tag,
            [arith_offset, arith_length, arith_code_size, _, arith_real_len, arith_zero_len, arith_real_len_is_zero, arith_zero_len_is_zero],
        ) = extract_lookup_expression!(arithmetic, length_entry);
        let (_, _, _, _, _, _, _, _, _, copy_lookup_len, _) =
            extract_lookup_expression!(copy, copy_lookup_entry.clone());
        let (_, _, _, _, _, _, _, _, _, copy_padding_lookup_len, _) =
            extract_lookup_expression!(copy, copy_padding_lookup_entry.clone());
        let (
            public_codesize_tag,
            _,
            [public_code_addr_hi, public_code_addr_lo, public_code_size_hi, public_code_size_lo],
        ) = extract_lookup_expression!(public, public_code_size_entry);

        let mut constraints = vec![];

        // stack constraints
        // index0: dst_offset, index1: offset, index2: len
        let mut copy_code_stamp_start = 0.expr();
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
                copy_code_stamp_start = stamp;
            }
        }

        //  code copy constraints
        constraints.extend(config.get_copy_constraints(
            copy::Tag::Bytecode,
            address.clone(),
            stack_pop_values[1][1].clone(), // stack top1 value_lo
            0.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_pop_values[0][1].clone(), // stack top0 value_lo
            copy_code_stamp_start.clone() + 1.expr(),
            None,
            arith_real_len.clone(), // stack top2 value_lo
            arith_real_len_is_zero.expr(),
            None,
            copy_lookup_entry.clone(),
        ));

        constraints.extend(config.get_copy_constraints(
            copy::Tag::Zero,
            0.expr(),
            0.expr(),
            0.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_pop_values[0][1].clone() + copy_lookup_len.clone(),
            copy_code_stamp_start.clone() + copy_lookup_len.clone() + 1.expr(),
            None,
            arith_zero_len.clone(), // stack top2 value_lo
            arith_zero_len_is_zero.expr(),
            None,
            copy_padding_lookup_entry.clone(),
        ));

        // because the values of destOffset, offset, and length are all in the u64 range, all value_hi is 0
        constraints.extend([
            (
                "stack top0 value_hi = 0".into(),
                stack_pop_values[0][0].clone(),
            ),
            (
                "stack top2 value_hi = 0".into(),
                stack_pop_values[2][0].clone(),
            ),
        ]);

        let src_not_overflow = SimpleIsZero::new(
            &src_overflow,
            &src_overflow_inv,
            "src offset overflow".into(),
        );
        constraints.extend([
            (
                "src_offset_hi = stack top1 value_hi".into(),
                stack_pop_values[1][0].clone() - src_offset_hi.clone(),
            ),
            (
                "src_offset_lo = stack top1 value_lo".into(),
                stack_pop_values[1][1].clone() - src_offset_lo.clone(),
            ),
            (
                "offset in length arithmetic = src_not_overflow * stack top1 value + src_overflow * MAX_CODESIZE".into(),
                src_not_overflow.expr() * (stack_pop_values[1][0].clone() * pow_of_two::<F>(128)+  stack_pop_values[1][1].clone())
                    + (1.expr() - src_not_overflow.expr()) * (MAX_CODESIZE).expr()
                    - arith_offset.clone(),
            ),
        ]);

        // length constraints
        constraints.extend([(
            "arith length = stack top2 value".into(),
            arith_length.clone()
                - (stack_pop_values[2][0].clone() * pow_of_two::<F>(128)
                    + stack_pop_values[2][1].clone()),
        )]);

        // public code size constraints
        constraints.extend([
            (
                "public code size tag".into(),
                public_codesize_tag - (public::Tag::CodeSize as u8).expr(),
            ),
            (
                "code address = (public_value[0] << 128) + public_values[1]".into(),
                public_code_addr_hi.clone() * pow_of_two::<F>(128) + public_code_addr_lo.clone()
                    - address.clone(),
            ),
            // code size must <= u64::MAX
            (
                "public code size hi = 0".into(),
                public_code_size_hi.clone(),
            ),
            (
                "public code size lo = size in length_arithmetic".into(),
                public_code_size_lo.clone() - arith_code_size.clone(),
            ),
        ]);

        // memory chunk
        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        // arithmetic_operands_full has 4 elements: [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size]
        let (
            arith_memory_expand_tag,
            [offset_bound, memory_chunk_prev, expansion_tag, access_memory_size],
        ) = extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 5));

        let length = stack_pop_values[2][1].clone();
        let length_inv = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );

        // constraint that length_inv is length's inverse
        let length_is_zero = SimpleIsZero::new(&length, &length_inv, String::from("length_lo"));
        constraints.extend(length_is_zero.get_constraints());

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
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            Rotation::cur(),
        );
        constraints.push((
            "memory_size_for_next ==  (mem_off + length) * (1 - is_zero_len.expr()) in state lookup".into(),
            (stack_pop_values[0][1].clone() + length.clone()) * (1.expr() - length_is_zero.expr())
                - memory_size_for_next.clone(),
        ));

        let memory_chunk_prev_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 2],
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
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 3],
            Rotation::cur(),
        );
        constraints.push((
            "length_for_next == length in state lookup".into(),
            length_for_next - length.clone(),
        ));

        // Add constraints for arithmetic tag.
        constraints.extend(vec![
            (
                "arithmetic tag is MemoryExpansion".into(),
                arith_memory_expand_tag.clone() - (arithmetic::Tag::MemoryExpansion as u8).expr(),
            ),
            (
                "arithmetic tag is Length".into(),
                arith_length_tag.clone() - (arithmetic::Tag::Length as u8).expr(),
            ),
            (
                "arithmetic tag is overflow".into(),
                arith_src_overflow_tag.clone() - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
        ]);

        // auxiliary constraints
        // code_copy will increase the stamp automatically
        // state_stamp_delta = STATE_STAMP_DELTA + len(copied code)
        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr()
                    + copy_lookup_len.clone()
                    + copy_padding_lookup_len.clone(),
            ),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::To(memory_chunk_to),
            gas_left: ExpressionOutcome::Delta(0.expr()), // call data copy最终的gas有memory_copier_gas决定
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(
            meta,
            NUM_ROW,
            auxiliary_delta.clone(),
        ));
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, auxiliary_delta));

        // pc后移至memory_copier_gas后变化
        let core_single_delta = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(MEMORY_GAS, memory_gas_cost::NUM_ROW, None)],
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
        let code_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let padding_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 1));

        // src_offfset overflow lookup
        let arith_src_overflow_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 4));

        // arithmetic memory_expansion lookup
        let arith_memory =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        // arithmetic_lengh lookup
        let arith_length_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_lookup_with_rotation(meta, 1, Rotation(-3))
        });

        // public code size lookup
        let public_code_size_lookup = query_expression(meta, |meta| {
            config.get_public_lookup_with_rotation(meta, 0, Rotation(-3))
        });

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
            ("code copy lookup".into(), code_copy_lookup),
            ("code copy padding lookup".into(), padding_copy_lookup),
            (
                "arithmetic memory expansion tiny lookup".into(),
                arith_memory,
            ),
            ("arithmetic_length lookup".into(), arith_length_lookup),
            (
                "arithmetic_overflow lookup(src offset)".into(),
                arith_src_overflow_lookup,
            ),
            ("public code size lookup".into(), public_code_size_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CODECOPY);

        // get dstOffset、offset、length from stack top
        let (stack_pop_mem_offset, mem_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_code_offset, code_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate copy rows and state rows(type: memory)
        let (
            copy_rows,
            state_memory_rows,
            arith_length_rows,
            arith_src_overflow_rows,
            public_code_size_row,
            real_length,
            zero_length,
            _,
        ) = current_state.get_code_copy_rows::<F>(
            current_state.code_addr,
            code_offset,
            mem_offset,
            length,
            false,
        );

        let mut copy_row = &Default::default();
        if real_length > 0 {
            copy_row = &copy_rows[0];
        }

        let mut padding_row = &Default::default();
        if zero_length > 0 {
            padding_row = &copy_rows[real_length as usize];
        }

        // generate core rows
        // core row3
        let mut core_row_3 = current_state.get_core_row_without_versatile(&trace, 3);
        // insert length rows
        core_row_3.insert_arithmetic_lookup(0, &arith_length_rows);
        // insert public code size rows
        core_row_3.insert_public_lookup(0, &public_code_size_row);

        // core row2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // insert lookUp, src: Core circuit, target: Copy circuit table
        core_row_2.insert_copy_lookup(0, copy_row);
        core_row_2.insert_copy_lookup(1, padding_row);
        // insert src_offset u64 overflow rows in index 4
        core_row_2.insert_arithmetic_tiny_lookup(4, &arith_src_overflow_rows);
        // memory expansion
        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if length.is_zero() {
            U256::zero()
        } else {
            mem_offset + length
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);
        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        // core row1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_pop_mem_offset,
            &stack_pop_code_offset,
            &stack_pop_length,
        ]);

        // core row0
        let mut core_row_0 = ExecutionState::CODECOPY.into_exec_state_core_row(
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
        current_state.length_in_stack = length.as_u64();
        current_state.new_memory_size = offset_bound.as_u64();

        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());

        // 固定的预分配位置
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            offset_bound
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 2],
            current_state.memory_chunk_prev.into()
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 3],
            length.into()
        );

        let mut arith_rows = vec![];
        // src offset u64 overflow rows
        arith_rows.extend(arith_src_overflow_rows);
        // input length rows
        arith_rows.extend(arith_length_rows);
        // memory expansion rows
        arith_rows.extend(arith_mem);

        let mut state_rows = vec![
            stack_pop_mem_offset,
            stack_pop_code_offset,
            stack_pop_length,
        ];
        state_rows.extend(state_memory_rows);

        // put rows into the Witness object
        Witness {
            core: vec![core_row_3, core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
            arithmetic: arith_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CodecopyGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use eth_types::Word;
    use std::vec;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint_copy_no_padding() {
        run_prover(&[2.into(), 0.into(), 0.into()]);
    }

    #[test]
    fn assign_and_constraint_src_overflow_only_padding() {
        // code size is 3 , only padding
        run_prover(&[2.into(), U256::MAX, 0.into()]);
    }
    #[test]
    fn assign_and_constraint_copy_padding() {
        run_prover(&[5.into(), 0.into(), 0.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_no_padding() {
        run_prover(&[0.into(), 0.into(), 0.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_only_padding() {
        run_prover(&[5.into(), 4.into(), 0.into()]);
    }

    fn run_prover(words: &[Word]) {
        let stack = Stack::from_slice(words);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let mut code_vec = vec![];
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::ADD.as_u8());
        current_state
            .bytecode
            .insert(0xaa.into(), code_vec.to_vec().into());
        current_state.code_addr = 0xaa.into();
        current_state.memory_chunk_prev = 256;
        current_state.memory_chunk = 256;
        current_state.gas_left = 100;

        let trace = prepare_trace_step!(0, OpcodeId::CODECOPY, stack);
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
