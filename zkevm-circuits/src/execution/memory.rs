use crate::constant::INDEX_STACK_POINTER;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
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
///
/// +---+-------+--------+--------+----------+
/// |cnt| 8 col | 8 col  | 8 col  | 8 col    |
/// +---+-------+--------+--------+----------+
/// | 2 | COPY1(11) | COPY2(11) |            |
/// | 1 | STATE1| STATE2 |                   |
/// | 0 | DYNA_SELECTOR         | AUX        |
/// +---+-------+--------+--------+----------+
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
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(
                STACK_POINTER_DELTA_MLOAD.expr()
                    * (OpcodeId::MSTORE.as_u8().expr() - opcode.clone())
                    + STACK_POINTER_DELTA_MSTORE.expr()
                        * (opcode.clone() - OpcodeId::MLOAD.as_u8().expr()),
            ), //the property OpcodeId::MSTORE - OpcodeId::MLOAD == 1 is used
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
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
                config.get_copy_lookup(meta)
            } else {
                config.get_copy_padding_lookup(meta)
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
        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            (opcode.clone() - OpcodeId::MLOAD.expr()) * (opcode - OpcodeId::MSTORE.expr()),
        )]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let copy_lookup_0 = query_expression(meta, |meta| config.get_copy_lookup(meta));
        let copy_lookup_1 = query_expression(meta, |meta| config.get_copy_padding_lookup(meta));

        vec![
            ("stack lookup 0".into(), stack_lookup_0),
            ("stack lookup 1".into(), stack_lookup_1),
            ("copy lookup 0".into(), copy_lookup_0),
            ("copy lookup 1".into(), copy_lookup_1),
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

        state_rows.extend(vec![stack_row_0.clone(), stack_row_1.clone()]);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&stack_row_0, &stack_row_1]);
        let core_row_0 = ExecutionState::MEMORY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
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
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + INDEX_STACK_POINTER] =
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
    #[test]
    fn assign_and_constraint_mstore() {
        let value = U256::from_big_endian(&[0x12; 32]);
        let stack = Stack::from_slice(&[value, 0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
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
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + INDEX_STACK_POINTER] =
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
