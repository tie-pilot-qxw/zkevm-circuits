// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
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
///
/// todo: will use the Length operation method of the arithmetic circuit to calculate normal_length, zero_length based on length, offset, len(Bytecode)
///
/// Table layout:
///     COPY: normal length Copy Lookup, src:Core circuit, target:Copy circuit table, 9 columns
///     ZEROCOPY: zero length Copy Lookup, src:Core circuit, target:Copy circuit table, 9 columns
///     COPY_LEN_LO: normal length
///     COPY_LEN_INV: the multiplicative inverse of normal_length, used to determine whether normal_length is 0,please refer to the usage of SimpleIsZero
///     ZERO_LEN_LO: zero padding length,
///     ZERO_LEN_INV: the multiplicative inverse of zero_length, used to determine whether zero_length is 0
/// +---+-------+-------+-------+---------+
/// |cnt| 8 col | 8 col | 8 col |  8col   |
/// +---+-------+-------+-------+---------+
/// | 2 | COPY(9)| ZEROCOPY(9) | COPY_LEN_LO(1) | COPY_LEN_INV(1) | ZERO_LEN_LO(1) | ZERO_LEN_INV(1)
/// | 1 | STATE | STATE | STATE | notUsed |
/// | 0 | DYNA_SELECTOR   | AUX           |
/// +---+-------+-------+-------+---------+

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -3;
const START_OFFSET: usize = 22;
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
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let address = meta.query_advice(config.code_addr, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let copy_lookup_entry = config.get_copy_lookup(meta);
        let copy_padding_lookup_entry = config.get_copy_padding_lookup(meta);

        let (_, _, _, _, _, _, _, _, _, copy_lookup_len, _) =
            extract_lookup_expression!(copy, copy_lookup_entry.clone());
        let (_, _, _, _, _, _, _, _, _, copy_padding_lookup_len, _) =
            extract_lookup_expression!(copy, copy_padding_lookup_entry.clone());

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
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

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

        //  add normal_length copy constraints
        let copy_len_lo = meta.query_advice(config.vers[22], Rotation(-2));
        let copy_len_lo_inv = meta.query_advice(config.vers[23], Rotation(-2));
        let copy_len_is_zero =
            SimpleIsZero::new(&copy_len_lo, &copy_len_lo_inv, String::from("copy_len_lo"));
        constraints.extend(copy_len_is_zero.get_constraints());

        constraints.extend(config.get_copy_constraints(
            copy::Tag::Bytecode,
            address,
            stack_pop_values[1][1].clone(), // stack top1 value_lo
            0.expr(),
            copy::Tag::Memory,
            call_id.clone(),
            stack_pop_values[0][1].clone(), // stack top0 value_lo
            copy_code_stamp_start.clone() + 1.expr(),
            None,
            copy_len_lo.clone(), // stack top2 value_lo
            copy_len_is_zero.expr(),
            None,
            copy_lookup_entry.clone(),
        ));

        // add zero_padding length copy constraints
        let copy_padding_len_lo = meta.query_advice(config.vers[24], Rotation(-2));
        let copy_padding_len_lo_inv = meta.query_advice(config.vers[25], Rotation(-2));
        let copy_padding_len_is_zero = SimpleIsZero::new(
            &copy_padding_len_lo,
            &copy_padding_len_lo_inv,
            String::from("copy_padding_len_lo"),
        );
        constraints.extend(copy_padding_len_is_zero.get_constraints());

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
            copy_padding_len_lo.clone(), // stack top2 value_lo
            copy_padding_len_is_zero.expr(),
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
                "stack top1 value_hi = 0".into(),
                stack_pop_values[1][0].clone(),
            ),
            (
                "stack top2 value_hi = 0".into(),
                stack_pop_values[2][0].clone(),
            ),
            // todo: use arithmetic, when generating witness, stack top2 value_lo will be truncated to u64(input_copy_len)
            // (
            //     "stack top2 value_lo(input_len) = copy_lookup_len+padding_lookup_len".into(),
            //     stack_pop_values[2][1].clone() - copy_lookup_len - copy_padding_lookup_len,
            // ),
            // (
            //     "stack top2 value_lo(input_len) = copy_len_lo+padding_len_lo".into(),
            //     stack_pop_values[2][1].clone() - copy_len_lo - copy_padding_len_lo,
            // ),
        ]);

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
        let code_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));
        let padding_copy_lookup =
            query_expression(meta, |meta| config.get_copy_padding_lookup(meta));
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
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CODECOPY);

        // get dstOffset、offset、length from stack top
        let (stack_pop_mem_offset, mem_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_code_offset, code_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows, _, padding_len, code_copy_len) = current_state
            .get_code_copy_rows::<F>(current_state.code_addr, mem_offset, code_offset, length);

        let mut copy_row = &Default::default();
        if code_copy_len > 0 {
            copy_row = &copy_rows[0];
        }

        let mut padding_row = &Default::default();
        if padding_len > 0 {
            padding_row = &copy_rows[code_copy_len as usize];
        }

        // insert lookUp, src: Core circuit, target: Copy circuit table
        core_row_2.insert_copy_lookup(0, copy_row);
        core_row_2.insert_copy_lookup(1, padding_row);
        // calculate the multiplicative inverse of normal_length, used to determine whether normal_length is 0
        let code_copy_len_lo = F::from(code_copy_len);
        let code_copy_len_lo_inv = U256::from_little_endian(
            code_copy_len_lo
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        // calculate the multiplicative inverse of zero_length, used to determine whether zero_length is 0
        let padding_copy_len_lo = F::from(padding_len);
        let padding_copy_len_lo_inv = U256::from_little_endian(
            padding_copy_len_lo
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        let column_values = [
            U256::from(code_copy_len),
            code_copy_len_lo_inv,
            U256::from(padding_len),
            padding_copy_len_lo_inv,
        ];
        for i in 0..4 {
            assign_or_panic!(core_row_2[i + START_OFFSET], column_values[i]);
        }
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_pop_mem_offset,
            &stack_pop_code_offset,
            &stack_pop_length,
        ]);

        let core_row_0 = ExecutionState::CODECOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![
            stack_pop_mem_offset,
            stack_pop_code_offset,
            stack_pop_length,
        ];
        state_rows.extend(memory_state_rows);

        // put rows into the Witness object
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
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
        let trace = prepare_trace_step!(0, OpcodeId::CODECOPY, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[19] = Some(stack_pointer.into());
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
