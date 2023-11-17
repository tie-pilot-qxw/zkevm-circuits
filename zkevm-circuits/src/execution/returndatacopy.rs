// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.
use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -3;
const PC_DELTA: u64 = 1;

/// ReturnDataCopy Execution State layout is as follows
/// where STATE means state table lookup,
/// Copy means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+---------+
/// |cnt| 8 col | 8 col | 8 col |  8col   |
/// +---+-------+-------+-------+---------+
/// | 2 | COPY(9)|
/// | 1 | STATE | STATE | STATE |         |
/// | 0 | DYNA_SELECTOR   | AUX           |
/// +---+-------+-------+-------+---------+
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
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let copy_entry = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, len) = extract_lookup_expression!(copy, copy_entry.clone());

        // code_copy will increase the stamp automatically
        // state_stamp_delta = STATE_STAMP_DELTA + copy_lookup_len(copied code)
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + (len.clone() * 2.expr()),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // index0: dst_offset, index1: offset, index2:             copy_lookup_len,
        let mut top2_stamp = 0.expr();
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

            constraints.extend([(format!("value_high_{} = 0", i), value_hi.expr())]);

            stack_pop_values.push(value_lo);
            if i == 2 {
                top2_stamp = stamp;
            }
        }

        let len_lo_inv = meta.query_advice(config.vers[24], Rotation::prev());

        let is_zero_len =
            SimpleIsZero::new(&stack_pop_values[2], &len_lo_inv, String::from("lengthlo"));

        let is_copydata_exceed_len = meta.query_advice(config.vers[25], Rotation::prev());

        constraints.append(&mut config.get_copy_contraints(
            copy::Type::Returndata,
            call_id.clone(),
            stack_pop_values[1].clone(),
            top2_stamp.clone() + 1.expr(),
            copy::Type::Memory,
            call_id,
            stack_pop_values[0].clone(),
            top2_stamp + stack_pop_values[2].clone() + 1.expr(),
            stack_pop_values[2].clone(),
            is_zero_len.expr(),
            copy_entry,
        ));

        constraints.extend([
            (
                "opcode is RETURNDATACOPY".into(),
                opcode - (OpcodeId::RETURNDATACOPY).expr(),
            ),
            ("next pc ".into(), pc_next - pc_cur - PC_DELTA.expr()),
            (
                "copydata not exceed returndate length".into(),
                is_copydata_exceed_len.expr(),
            ),
        ]);
        // TODO: add return data length > copy size

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
            ("returndata copy lookup".into(), code_copy_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::RETURNDATACOPY);

        // get dstOffset、offset、length from stack top
        let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // generate copy rows and state rows(type: memory)
        let (copy_rows, copy_state_rows) = current_state.get_return_data_copy_rows(
            dst_offset.as_usize(),
            offset.as_usize(),
            length.as_usize(),
        );
        // insert lookUp: Core ---> Copy
        if length == 0.into() {
            core_row_2.insert_copy_lookup(&copy::Row {
                byte: 0.into(),
                src_type: copy::Type::default(),
                src_id: 0.into(),
                src_pointer: 0.into(),
                src_stamp: 0.into(),
                dst_type: copy::Type::default(),
                dst_id: 0.into(),
                dst_pointer: 0.into(),
                dst_stamp: 0.into(),
                cnt: 0.into(),
                len: 0.into(),
            });
        } else {
            core_row_2.insert_copy_lookup(&copy_rows[0]);
        }

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let len_lo = F::from_u128(length.low_u128());
        let lenlo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());

        //lenlo_inv
        assign_or_panic!(core_row_1.vers_24, lenlo_inv);

        // get returndata_size
        let returndata_size = current_state
            .return_data
            .get(&current_state.call_id)
            .map(|v| v.len())
            .unwrap_or_default();

        if (offset + length) > U256::from(returndata_size) {
            assign_or_panic!(core_row_1.vers_25, U256::from(1));
        } else {
            assign_or_panic!(core_row_1.vers_25, U256::zero());
        };

        let core_row_0 = ExecutionState::RETURNDATACOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![stack_pop_dst_offset, stack_pop_offset, stack_pop_length];
        state_rows.extend(copy_state_rows);
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
    Box::new(ReturndatacopyGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        //add WitnessExecHelper test retur_data 数据
        let stack = Stack::from_slice(&[0.into(), 0.into(), 2.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(0xff.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::RETURNDATACOPY, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
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
