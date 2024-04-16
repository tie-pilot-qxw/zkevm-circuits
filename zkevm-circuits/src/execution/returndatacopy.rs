use crate::arithmetic_circuit::operation::{self, u64overflow};
use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
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
const OVERFLOW_COL_IDX: usize = 30;

/// ReturnDataCopy Execution State layout is as follows
/// where RSSTATE means return data size state table lookup
/// STATE means state table lookup(call_context read returndata_call_id, stack pop dst_offset, stack_pop offset, stack_pop length),
/// ARITH(9) means return data size - (offset+length)
/// LI(1) means length lo inv
/// OAF(4) means arithmetic overflow of offset
/// OLF(4) means arithmetic overflow of sum(offset , length)
/// OF(1) means return data size - (offset+length) >= 0
/// Copy(CP) means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-----------------------+-------+---------+
/// |cnt| 8 col |           8 col       | 8 col |  8col   |
/// +---+-------+-----------------------+-------+---------+
/// | 3 |RSSTATE|                       |       |         |
/// | 2 |ARITH(9) |LI(1)|     |CP(11) |OAF(4)|OLF(4)|OF(1)|
/// | 1 | STATE |        STATE          | STATE | STATE   |
/// | 0 |       DYNA_SELECTOR             | AUX           |
/// +---+-------+-----------------------+-------+---------+
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
        (NUM_ROW, 1)
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
        // get arithmetic lookup
        let less_arithmetic_entry = config.get_arithmetic_lookup(meta, 0);
        let (less_arithmetic_tag, less_arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, less_arithmetic_entry.clone());
        // get arithmetic overflow lookup
        let overflow_entry = config.get_arithmetic_u64overflow_lookup(meta, 0);
        let [overflow_value_hi, overflow_value_lo, overflow, overflow_inv] =
            extract_lookup_expression!(arithmetic_u64, overflow_entry.clone());
        // get offset plus length overflow lookup
        let offset_plus_length_overflow_entry = config.get_arithmetic_u64overflow_lookup(meta, 1);
        let [offset_plus_length_value_hi, offset_plus_length_value_lo, offset_plus_length_overflow, offset_plus_length_overflow_inv] =
            extract_lookup_expression!(arithmetic_u64, offset_plus_length_overflow_entry.clone());
        // code_copy will increase the stamp automatically
        // state_stamp_delta = STATE_STAMP_DELTA + copy_lookup_len(copied code)
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + (len.clone() * 2.expr()),
            ),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

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

        // offset overflow constraints
        let not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "offset u64 overflow".into());
        constraints.extend([
            ("not overflow".into(), not_overflow.expr() - 1.expr()),
            ("overflow value hi = 0".into(), overflow_value_hi),
            (
                "overflow value lo = state_values[2]".into(),
                overflow_value_lo - state_values[2].clone(),
            ),
        ]);
        // offset plus length overflow constraints
        let offset_plus_length_not_overflow = SimpleIsZero::new(
            &offset_plus_length_overflow,
            &offset_plus_length_overflow_inv,
            "offset plus length u64 overflow".into(),
        );
        constraints.extend([
            (
                "offset plus length not overflow".into(),
                offset_plus_length_not_overflow.expr() - 1.expr(),
            ),
            (
                "offset plus length hi = 0".into(),
                offset_plus_length_value_hi,
            ),
            (
                "offset plus length lo = state_values[2] + state_values[3]".into(),
                offset_plus_length_value_lo - state_values[2].clone() - state_values[3].clone(),
            ),
        ]);
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation(-2));
        let is_zero_len =
            SimpleIsZero::new(&state_values[3], &len_lo_inv, String::from("length_lo"));
        constraints.append(&mut is_zero_len.get_constraints());

        let offset_plus_length = state_values[3].clone() + state_values[2].clone();
        let overflow_flag = meta.query_advice(config.vers[OVERFLOW_COL_IDX], Rotation(-2));
        // length + offset <= return_data_size
        // arithmetic constraints
        // arithmetic_operands_full[0] = return_data_size_hi
        // arithmetic_operands_full[1] = return_data_size_lo
        // arithmetic_operands_full[2] = 0
        // arithmetic_operands_full[3] = offset_plus_length
        // arithmetic_operands_full[6] = 0
        // arithmetic_operands_full[7] = overflow_flag
        constraints.extend([
            (
                "arithmetic tag is sub".into(),
                less_arithmetic_tag - (arithmetic::Tag::Sub as u8).expr(),
            ),
            (
                "arithmetic_operands_full[0] = return_data_size_hi".into(),
                less_arithmetic_operands_full[0].clone() - returndata_size_hi.clone(),
            ),
            (
                "arithmetic_operands_full[1] = return_data_size_lo".into(),
                less_arithmetic_operands_full[1].clone() - returndata_size_lo.clone(),
            ),
            (
                "arithmetic_operands_full[2] = 0".into(),
                less_arithmetic_operands_full[2].clone(),
            ),
            (
                "arithmetic_operands_full[3] = offset_plus_length".into(),
                less_arithmetic_operands_full[3].clone() - offset_plus_length,
            ),
            (
                "arithmetic_operands_full[6] = overflow_flag".into(),
                less_arithmetic_operands_full[6].clone() - overflow_flag,
            ),
            (
                "arithmetic_operands_full[7] = 0".into(),
                less_arithmetic_operands_full[7].clone(),
            ),
        ]);

        let returndata_call_id = state_values[0].clone();
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Returndata,
            returndata_call_id.clone(),
            state_values[2].clone(),
            top2_stamp.clone() + 2.expr(),
            copy::Tag::Memory,
            call_id,
            state_values[1].clone(),
            top2_stamp + state_values[3].clone() + 2.expr(),
            None,
            state_values[3].clone(),
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
            CoreSinglePurposeOutcome {
                pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
                ..Default::default()
            },
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
        let less_arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        let overflow_arithmetic_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_u64overflow_lookup(meta, 0)
        });
        let offset_plus_length_overflow_arithmetic_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_u64overflow_lookup(meta, 1)
        });
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
            ("arithmetic less sub lookup".into(), less_arithmetic_lookup),
            (
                "arithmetic overflow lookup".into(),
                overflow_arithmetic_lookup,
            ),
            (
                "offset plus length overflow lookup".into(),
                offset_plus_length_overflow_arithmetic_lookup,
            ),
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
        // insert offset overflow arithmetic
        let (mut dest_offset_overflow_arith, _) = u64overflow::gen_witness::<F>(vec![offset]);
        core_row_2.insert_arithmetic_u64overflow_lookup(0, &dest_offset_overflow_arith);
        // insert offset + length overflow arithmetic
        let (mut offset_plus_length_overflow_arith, _) =
            u64overflow::gen_witness::<F>(vec![offset + length]);
        core_row_2.insert_arithmetic_u64overflow_lookup(1, &offset_plus_length_overflow_arith);
        let len_lo = F::from_u128(length.low_u128());
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        //lenlo_inv
        assign_or_panic!(core_row_2[LEN_LO_INV_COL_IDX], len_lo_inv);

        // 若不满足,应该在trace中有ErrReturnDataOutOfBounds
        assert!(offset + length <= returndata_size);
        let (mut less_arithmetic_rows, arithmetic_result) =
            operation::sub::gen_witness(vec![returndata_size, offset + length]);
        core_row_2.insert_arithmetic_lookup(0, &less_arithmetic_rows);
        assign_or_panic!(core_row_2[OVERFLOW_COL_IDX], arithmetic_result[1]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &call_context_read,
            &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let core_row_0 = ExecutionState::RETURNDATACOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
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
        arithmetic_rows.append(&mut dest_offset_overflow_arith);
        arithmetic_rows.append(&mut offset_plus_length_overflow_arith);
        arithmetic_rows.append(&mut less_arithmetic_rows);
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
