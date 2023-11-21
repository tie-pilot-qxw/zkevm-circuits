// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{copy, Witness, WitnessExecHelper};

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
/// where COPY means copy table lookup , 9 cols
/// STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+---------+---------+
/// |cnt| 8 col | 8 col |  8 col  |  8col   |
/// +---+-------+-------+---------+---------+
/// | 2 | Copy(9) |                   |
/// | 1 | STATE | STATE | notUsed | notUsed |
/// | 0 | DYNA_SELECTOR | AUX               |
/// +---+-------+-------+---------+---------+
///

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = -2;
const PC_DELTA: u64 = 1;

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

        // build constraints ---
        // append auxiliary constraints
        let copy_entry = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, len) = extract_lookup_expression!(copy, copy_entry.clone());
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // append stack constraints
        let mut stack_pop_values = vec![];
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
        }

        // append core single purpose constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        // append return&revert constraints
        let len_lo_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let is_zero_len =
            SimpleIsZero::new(&stack_pop_values[3], &len_lo_inv, String::from("length_lo"));

        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 1));

        constraints.append(&mut config.get_copy_contraints(
            copy::Type::Memory,
            call_id.clone(),
            stack_pop_values[1].clone(),
            stamp.clone() + 1.expr(),
            copy::Type::Returndata,
            call_id,
            0.expr(),
            stamp.clone() + stack_pop_values[3].clone() + 1.expr(),
            stack_pop_values[3].clone(),
            is_zero_len.expr(),
            copy_entry,
        ));

        // extend opcode and pc constraints
        constraints.extend([
            (
                format!("opcode is RETURN or REVERT").into(),
                (opcode.clone() - (OpcodeId::RETURN).expr()) * (opcode - (OpcodeId::REVERT).expr()),
            ),
            (
                format!("next pc").into(),
                pc_next - pc_cur - PC_DELTA.expr(),
            ),
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
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));
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
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get dstOffset、offset、length from stack top
        // let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        //update returndata_call_id and returndata_call_size
        current_state.returndata_call_id = current_state.call_id.clone();
        current_state.returndata_size = length;

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows) =
            current_state.get_return_revert_rows(trace, offset.as_usize(), length.as_usize());
        // insert lookUp: Core ---> Copy
        if length.is_zero() {
            core_row_2.insert_copy_lookup(&Default::default(), None);
        } else {
            core_row_2.insert_copy_lookup(&copy_rows[0], None);
        }

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        let len_lo = F::from_u128(length.low_u128());
        let lenlo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_24 = Some(lenlo_inv);

        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            // &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let core_row_0 = ExecutionState::RETURN_REVERT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![stack_pop_offset, stack_pop_length];
        state_rows.extend(memory_state_rows);
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
    Box::new(ReturnRevertGadget {
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
        let stack = Stack::from_slice(&[0x04.into(), 0x01.into()]); // len=4, offset=1
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
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
