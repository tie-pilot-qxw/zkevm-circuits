// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// +---+-------+-------+-------+---------+
/// |cnt| 8 col | 8 col | 8 col |  8col   |
/// +---+-------+-------+-------+---------+
/// | 2 | CopyLookUp(9)|
/// | 1 | STATE | STATE | STATE | notUsed |
/// | 0 | DYNA_SELECTOR   | AUX           |
/// +---+-------+-------+-------+---------+

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -3;
const PC_DELTA: u64 = 1;
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
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let address = meta.query_advice(config.code_addr, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let (
            copy_lookup_src_type,
            copy_lookup_code_address,
            copy_lookup_offset,
            _,
            copy_lookup_dst_type,
            copy_lookup_dst_id,
            copy_lookup_dst_offset,
            copy_lookup_det_stamp,
            copy_lookup_len,
        ) = extract_lookup_expression!(copy, config.get_copy_lookup(meta));

        // code_copy will increase the stamp automatically
        // state_stamp_delta = STATE_STAMP_DELTA + len(copied code)
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + copy_lookup_len.clone(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // index0: dst_offset, index1: offset, index2: len
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
            stack_pop_values.push(value_hi);
            stack_pop_values.push(value_lo);
            if i == 2 {
                top2_stamp = stamp;
            }
        }

        constraints.extend([
            (
                "[code copy] next pc ".into(),
                pc_next - pc_cur - PC_DELTA.expr(),
            ),
            (
                "[code copy] stack top0 value_hi = 0".into(),
                stack_pop_values[0].expr() - 0.expr(),
            ),
            (
                "[code copy] lookup dst_offset = stack top0 value_lo".into(),
                stack_pop_values[1].expr() - copy_lookup_dst_offset,
            ),
            (
                "[code copy] stack top1 value_hi = 0".into(),
                stack_pop_values[2].expr() - 0.expr(),
            ),
            (
                "[code copy] lookup offset = stack top1 value_lo".into(),
                stack_pop_values[3].expr() - copy_lookup_offset,
            ),
            (
                "[code copy] stack top2 value_hi = 0".into(),
                stack_pop_values[4].expr() - 0.expr(),
            ),
            (
                "[code copy] lookup len = stack top2 value_lo".into(),
                stack_pop_values[5].expr() - copy_lookup_len,
            ),
            (
                "[code copy] lookup code address = code address".into(),
                copy_lookup_code_address - address,
            ),
            (
                "[code copy] lookup dst_id = call id".into(),
                copy_lookup_dst_id - call_id,
            ),
            (
                "[code copy] lookup dst_stamp = top2_stamp + 1".into(),
                copy_lookup_det_stamp - top2_stamp - 1.expr(),
            ),
            (
                "[code copy] src_type is ByteCode".into(),
                copy_lookup_src_type - (copy::Type::Bytecode as u8).expr(),
            ),
            (
                "[code copy] dst_type is Memory".into(),
                copy_lookup_dst_type - (copy::Type::Memory as u8).expr(),
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
            ("code copy lookup".into(), code_copy_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CODECOPY);

        // get dstOffset、offset、length from stack top
        let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows) = current_state.get_code_copy_rows(
            current_state.code_addr,
            dst_offset.as_usize(),
            offset.as_usize(),
            length.as_usize(),
        );
        // insert lookUp: Core ---> Copy
        core_row_2.insert_copy_lookup(&copy_rows[0]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let core_row_0 = ExecutionState::CODECOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![stack_pop_dst_offset, stack_pop_offset, stack_pop_length];
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
    Box::new(CodecopyGadget {
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
        let stack = Stack::from_slice(&[0x02.into(), 0x00.into(), 0x00.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, OpcodeId::CODECOPY, stack);
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
