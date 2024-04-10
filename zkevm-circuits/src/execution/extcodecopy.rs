use crate::arithmetic_circuit::operation;
use crate::constant::{GAS_LEFT_IDX, MAX_CODESIZE, NUM_AUXILIARY};
use crate::execution::ExecutionState::MEMORY_GAS;
use crate::execution::{
    memory_gas_cost, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{
    arithmetic, assign_or_panic, copy, public, state, Witness, WitnessExecHelper,
};
use eth_types::evm_types::GasCost;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 5;
const ADDRESS_ZERO_COUNT: u32 = 12 * 8;
const STATE_STAMP_DELTA: u64 = 6;
const STACK_POINTER_DELTA: i32 = -4;
const PC_DELTA: u64 = 1;

/// Extcodecopy Execution State layout is as follows
/// where COPY means copy table lookup , 9 cols
/// ZEROCOPY means padding copy table lookup 9,cols
/// LENGTH(9) means length arithmetic table lookup, 9cols
/// PUB_CODE_SIZE(6) means public table lookup, 9 cols
/// LENGTH_INV means size's multiplicative inverse;
/// OVER_ARITH(5) means src offset overflow arithmetic lookup, 5 cols
/// EXP_ARITH(5) means memory expansion arithmetic lookup, 5 cols
/// STATE means state table lookup,
/// STATE0 means account address,
/// STATE1 means memOffset
/// STATE2 means codeOffset
/// STATE3 means length
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// OFFSET_BOUND (26) is `length + offset`
/// MEMORY_CHUNK_PREV (27) is the previous memory chunk
/// SIZE(28) is the opcode input parameter
/// WARM_GAS (29) is EIP2929 warm gas cost
/// +-----+------------------------+-------------------------+-------------------+----------------------+--------------------------+----------+--------------+
/// | cnt |                        |                         |                   |                      |                          |          |              |
/// +-----+------------------------+-------------------------+-------------------+----------------------+--------------------------+----------+--------------+
/// | 4   | STORAGE_READ (0.. 11)  | STORAGE_WRITE(12.. 23)  |                   |                      |                          |          |              |
/// | 3   | LENGTH(9)              |                         | PUB_CODE_SIZE(6)  |                      |                          |          |              |
/// | 2   | COPY                   | ZEROCOPY                | OVER_ARITH(5)     | EXP_ARITH(5)         |                          |          |              |
/// | 1   | STATE0                 | STATE1                  | STATE2            | STATE3               |                          |          |              |
/// | 0   | DYNA_SELECTOR          | AUX                     | LENGTH_INV(25)    | OFFSET_BOUND (26)    | MEMORY_CHUNK_PREV (27)   | SIZE(28) | WARM_GAS (29)|
/// +-----+------------------------+-------------------------+-------------------+----------------------+--------------------------+----------+--------------+

pub struct ExtcodecopyGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ExtcodecopyGadget<F>
{
    fn name(&self) -> &'static str {
        "EXTCODECOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::EXTCODECOPY
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let copy_entry = config.get_copy_lookup(meta, 0);
        let padding_entry = config.get_copy_lookup(meta, 1);
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
            extract_lookup_expression!(copy, copy_entry.clone());
        let (_, _, _, _, _, _, _, _, _, copy_padding_lookup_len, _) =
            extract_lookup_expression!(copy, padding_entry.clone());
        let (
            public_codesize_tag,
            _,
            [public_code_addr_hi, public_code_addr_lo, public_code_size_hi, public_code_size_lo],
        ) = extract_lookup_expression!(public, public_code_size_entry);

        let mut stack_operands = vec![];
        let mut copy_code_stamp_start = 0.expr();
        let mut constraints = vec![];

        // stack constraints
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, tmp_stamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, entry);
            if i == 3 {
                copy_code_stamp_start = tmp_stamp.clone();
            }
            stack_operands.push([value_hi, value_lo]);
        }

        // code copy constraints
        constraints.extend(config.get_copy_constraints(
            copy::Tag::Bytecode,
            stack_operands[0][0].clone() * pow_of_two::<F>(128) + stack_operands[0][1].clone(),
            stack_operands[2][1].clone(),
            0.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_operands[1][1].clone(),
            // +3 是因为新增了is_warm，导致state_stamp在原来的基础上又加了2
            copy_code_stamp_start.clone() + 3.expr(),
            None,
            arith_real_len,
            arith_real_len_is_zero,
            None,
            copy_entry.clone(),
        ));

        // padding copy constraints
        constraints.extend(config.get_copy_constraints(
            copy::Tag::Zero,
            0.expr(),
            0.expr(),
            0.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_operands[1][1].clone() + copy_lookup_len.clone(),
            copy_code_stamp_start.clone() + copy_lookup_len.clone() + 3.expr(),
            None,
            arith_zero_len,
            arith_zero_len_is_zero,
            None,
            padding_entry.clone(),
        ));
        constraints.extend([
            (
                "stack top1 value_hi = 0".into(),
                stack_operands[1][0].clone() - 0.expr(),
            ),
            (
                "stack top3 value_hi = 0".into(),
                stack_operands[3][0].clone() - 0.expr(),
            ),
        ]);

        // warm case gas cost constraints
        let mut is_warm = 0.expr();
        for i in 0..2 {
            let entry = config.get_storage_lookup(meta, i, Rotation(-4));
            let mut is_write = true;
            if i == 0 {
                let extracted = extract_lookup_expression!(storage, entry.clone());
                is_warm = extracted.3;
                is_write = false;
            }
            constraints.append(&mut config.get_storage_full_constraints_with_tag(
                meta,
                entry,
                i + 4, // 前面有4个state
                NUM_ROW,
                0.expr(),
                0.expr(),
                stack_operands[0][0].clone(),
                stack_operands[0][1].clone(),
                state::Tag::AddrInAccessListStorage,
                is_write,
            ));
        }

        let warm_gas = select::expr(
            is_warm,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );
        let warm_gas_in_table = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 4],
            Rotation::cur(),
        );
        constraints.push(("warm_gas correct".into(), warm_gas - warm_gas_in_table));

        // src offset u64 overflow constraints
        let src_not_overflow = SimpleIsZero::new(
            &src_overflow,
            &src_overflow_inv,
            "src offset overflow".into(),
        );
        constraints.extend([
            (
                "src_offset_hi = stack top2 value_hi".into(),
                stack_operands[2][0].clone() - src_offset_hi.clone(),
            ),
            (
                "src_offset_lo = stack top2 value_lo".into(),
                stack_operands[2][1].clone() - src_offset_lo.clone(),
            ),
            (
                "offset in length arithmetic = src_not_overflow * stack top2 value + src_overflow * MAX_CODESIZE".into(),
                src_not_overflow.expr() * (stack_operands[2][0].clone() * pow_of_two::<F>(128)+  stack_operands[2][1].clone())
                    + (1.expr() - src_not_overflow.expr()) * MAX_CODESIZE.expr()
                    - arith_offset.clone(),
            ),
        ]);
        // length constraints
        constraints.extend([(
            "arith length = stack top3 value".into(),
            arith_length.clone()
                - (stack_operands[3][0].clone() * pow_of_two::<F>(128)
                    + stack_operands[3][1].clone()),
        )]);
        // public code size constraints
        constraints.extend([
            (
                "public code size tag".into(),
                public_codesize_tag - (public::Tag::CodeSize as u8).expr(),
            ),
            (
                "public code address hi = stack_operands[0][0]".into(),
                public_code_addr_hi.clone() - stack_operands[0][0].clone(),
            ),
            (
                "public code address lo = stack_operands[0][1]".into(),
                public_code_addr_lo.clone() - stack_operands[0][1].clone(),
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

        let length = stack_operands[3][1].clone();
        let length_inv = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );

        // constraint that length_inv is length's inverse
        let length_is_zero = SimpleIsZero::new(&length, &length_inv, String::from("length_lo"));
        constraints.extend(length_is_zero.get_constraints());

        // constraint for arithmetic operand
        constraints.push((
            "offset_bound in arithmetic = (mem_off + length) * (1 - length_is_zero.expr()) in state lookup"
                .into(),
            (stack_operands[1][1].clone() + length.clone()) * (1.expr() - length_is_zero.expr())
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
        // auxiliary constraints
        constraints.extend(config.get_auxiliary_constraints(
            meta,
            NUM_ROW,
            auxiliary_delta.clone(),
        ));
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, auxiliary_delta));

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

        // next state constraints
        let memory_size_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            Rotation::cur(),
        );
        constraints.push((
            "memory_size_for_next ==  (mem_off + length) * (1 - is_zero_len.expr()) in state lookup".into(),
            (stack_operands[1][1].clone()+ length.clone()) * (1.expr() - length_is_zero.expr())
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

        // pc后移至memory_copier_gas后变化
        // note: 原本的code_addr约束是要求下一个状态code_addr == config.addr in cur, 相当于delta(0.expr())
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
        // stack lookups
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let stack_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        // copy lookups
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let padding_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 1));

        // src_offfset overflow lookup
        let arith_src_overflow_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 4));

        let arith_memory =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 5));

        let length_arith_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_lookup_with_rotation(meta, 0, Rotation(-3))
        });
        // public code size lookup
        let public_code_size_lookup = query_expression(meta, |meta| {
            config.get_public_lookup_with_rotation(meta, 0, Rotation(-3))
        });

        // is_warm lookup
        let is_warm_read_lookup = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-4))
        });
        let is_warm_write_lookup = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-4))
        });
        vec![
            ("stack pop account address".into(), stack_lookup_0),
            ("stack pop mem offset".into(), stack_lookup_1),
            ("stack pop code offset".into(), stack_lookup_2),
            ("stack pop length".into(), stack_lookup_3),
            ("copy look up".into(), copy_lookup),
            ("padding look up".into(), padding_copy_lookup),
            ("arithmetic memory tiny lookup".into(), arith_memory),
            (
                "overflow arithmetic tiny lookup(src offset)".into(),
                arith_src_overflow_lookup,
            ),
            ("length arithmetic lookup".into(), length_arith_lookup),
            ("public code size lookup".into(), public_code_size_lookup),
            ("is_warm read lookup".into(), is_warm_read_lookup),
            ("is_warm write lookup".into(), is_warm_write_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // pop address
        let (stack_pop_0, address) = current_state.get_pop_stack_row_value(&trace);
        // code_address must be 20 bytes
        assert!(address.leading_zeros() >= ADDRESS_ZERO_COUNT);
        // pop mem_offset
        let (stack_pop_1, mem_offset) = current_state.get_pop_stack_row_value(&trace);
        // pop code_offset
        let (stack_pop_2, code_offset) = current_state.get_pop_stack_row_value(&trace);
        // pop size
        let (stack_pop_3, size) = current_state.get_pop_stack_row_value(&trace);

        // core_row_4
        let (is_warm_read_row, is_warm) = current_state.get_addr_access_list_read_row(address);
        let is_warm_write_row =
            current_state.get_addr_access_list_write_row(address, true, is_warm);
        let mut core_row_4 = current_state.get_core_row_without_versatile(&trace, 4);
        core_row_4.insert_storage_lookups([&is_warm_read_row, &is_warm_write_row]);

        let warm_gas = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        };

        // get copy length, zero length,and copy_rows,mem_rows
        let (
            copy_rows,
            state_memory_rows,
            arith_length_rows,
            arith_src_overflow_rows,
            public_code_size_row,
            code_copy_length,
            padding_length,
            addr_exists,
        ) = current_state.get_code_copy_rows::<F>(address, code_offset, mem_offset, size, true);

        let mut copy_row = &Default::default();
        if code_copy_length > 0 {
            copy_row = &copy_rows[0];
        }
        let mut padding_row = &Default::default();
        if padding_length > 0 {
            padding_row = &copy_rows[code_copy_length as usize]
        }

        // generate core rows
        // core row3
        let mut core_row_3 = current_state.get_core_row_without_versatile(&trace, 3);
        // insert length rows
        core_row_3.insert_arithmetic_lookup(0, &arith_length_rows);
        // insert public code size rows
        core_row_3.insert_public_lookup(0, &public_code_size_row);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // start_offset column offset
        core_row_2.insert_copy_lookup(0, copy_row);
        core_row_2.insert_copy_lookup(1, padding_row);
        // insert src_offset u64 overflow rows in index 4
        core_row_2.insert_arithmetic_tiny_lookup(4, &arith_src_overflow_rows);

        // memory_expansion
        let memory_chunk_prev = U256::from(current_state.memory_chunk_prev);
        let offset_bound = if size.is_zero() {
            U256::zero()
        } else {
            mem_offset + size
        };

        let (arith_mem, result) =
            operation::memory_expansion::gen_witness(vec![offset_bound, memory_chunk_prev]);
        assert_eq!(result[0] == U256::one(), memory_chunk_prev < result[1]);
        core_row_2.insert_arithmetic_tiny_lookup(5, &arith_mem);

        // core row1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_pop_2, &stack_pop_3]);

        // core row0
        let mut core_row_0 = ExecutionState::EXTCODECOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let size_inv = U256::from_little_endian(
            F::from(size.low_u64())
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );

        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            size_inv
        );

        // 根据栈里的输入记录length和memory_size
        current_state.length_in_stack = size.as_u64();
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
            size.into()
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 4],
            warm_gas.into()
        );

        let mut arith_rows = vec![];
        // src offset u64 overflow rows
        arith_rows.extend(arith_src_overflow_rows);
        // input length rows
        arith_rows.extend(arith_length_rows);
        // memory expansion rows
        arith_rows.extend(arith_mem);

        let mut state_vec = vec![
            stack_pop_0,
            stack_pop_1,
            stack_pop_2,
            stack_pop_3,
            is_warm_read_row,
            is_warm_write_row,
        ];
        state_vec.extend(state_memory_rows);

        let public_rows = if addr_exists.is_zero() {
            vec![public_code_size_row]
        } else {
            vec![]
        };
        Witness {
            copy: copy_rows,
            core: vec![core_row_4, core_row_3, core_row_2, core_row_1, core_row_0],
            state: state_vec,
            arithmetic: arith_rows,
            public: public_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ExtcodecopyGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use eth_types::Word;
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint_copy_no_padding() {
        // code size is 3 , mock copy ,no padding
        run_prover(&[2.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_src_overflow_only_padding() {
        // code size is 3 , only padding
        run_prover(&[2.into(), U256::MAX, 0.into(), 0xaa.into()]);
    }
    #[test]
    fn assign_and_constraint_copy_padding() {
        // code size is 3 ,mock copy and padding
        run_prover(&[5.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_no_padding() {
        // code size is 3 ,mock do nothing
        run_prover(&[0.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_only_padding() {
        // code size is 3 , mock no copy ,only padding
        run_prover(&[5.into(), 2.into(), 4.into(), 0xaa.into()]);
    }

    fn run_prover(words: &[Word]) {
        let stack = Stack::from_slice(words);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            memory_chunk: (((words[0] + words[2]).as_u64()) + 31) / 32,
            gas_left: 100,
            ..WitnessExecHelper::new()
        };
        let mut code_vec = vec![];
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::ADD.as_u8());
        current_state
            .bytecode
            .insert(0xaa.into(), code_vec.to_vec().into());
        let trace = prepare_trace_step!(0, OpcodeId::EXTCODECOPY, stack);
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
