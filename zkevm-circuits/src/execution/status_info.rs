// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
const PC_DELTA: u64 = 1;
const TAG_IDX: usize = 8;

/// StatusInfo gadget:
/// The MSIZE opcode returns the size of the memory in bytes.
/// The PC opcode returns the current value of the program counter.
/// The GAS opcode returns the amount of gas left. (after this instruction)
/// The memory is always fully accessible. What this instruction tracks is the highest
/// offset that was accessed in the current execution.
/// The TAG is used to select between the three opcodes.
///  A first write or read to a bigger offset will trigger a memory expansion,
/// which will cost gas. The size is always a multiple of a word (32 bytes).
/// STATE: State lookup (stack_push), src: Core circuit, target: State circuit table, 8 columns
///
/// +---+-------+--------+--------+----------+
/// |cnt| 8 col | 8 col  | 8 col  | 8 col    |
/// +---+-------+--------+--------+----------+
/// | 1 | STATE | TAG |                      |
/// | 0 | DYNA_SELECTOR         | AUX        |
/// +---+-------+--------+--------+----------+

pub struct StatusInfoGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for StatusInfoGadget<F>
{
    fn name(&self) -> &'static str {
        "STATUS_INFO"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STATUS_INFO
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
        let mut constraints = vec![];

        // get tag
        let msize_tag = meta.query_advice(config.vers[TAG_IDX], Rotation::prev());
        let pc_tag = meta.query_advice(config.vers[TAG_IDX + 1], Rotation::prev());
        let gas_tag = meta.query_advice(config.vers[TAG_IDX + 2], Rotation::prev());

        // Create a simple selector with tag
        let selector = SimpleSelector::new(&[msize_tag.clone(), pc_tag.clone(), gas_tag.clone()]);
        // Add constraints for the selector.
        constraints.extend(selector.get_constraints());

        // Add constraints for opcode.
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.push((
            "opcode".into(),
            opcode
                - selector.select(&[
                    OpcodeId::MSIZE.as_u8().expr(),
                    OpcodeId::PC.as_u8().expr(),
                    OpcodeId::GAS.as_u8().expr(),
                ]),
        ));

        // Get the gas cost for the opcode.
        let gas_cost = selector.select(&[
            OpcodeId::MSIZE.constant_gas_cost().expr(),
            OpcodeId::PC.constant_gas_cost().expr(),
            OpcodeId::GAS.constant_gas_cost().expr(),
        ]);

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // Get the auxiliary constraints.
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        // Get the core single-purpose constraints.
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // get state lookup
        let state_entry = config.get_state_lookup(meta, 0);

        // Get the stack constraints.
        constraints.append(&mut config.get_stack_constraints(
            meta,
            state_entry.clone(),
            0,
            NUM_ROW,
            STACK_POINTER_DELTA.expr(),
            true,
        ));
        // Extract the value_hi and value_lo from the state lookup expression.
        let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, state_entry);

        // get status info
        let memory_chunk = meta.query_advice(config.get_auxiliary().memory_chunk, Rotation::cur());
        let pc = meta.query_advice(config.pc, Rotation::cur());
        let gas = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());

        // constrain value hi must be 0
        constraints.push(("value hi must be 0".into(), value_hi.clone()));

        // constrain value lo equal to memory_chunk, pc or gas
        constraints.push((
            "value lo equal to memory_chunk, pc or gas".into(),
            value_lo.clone()
                - selector.select(&[memory_chunk.clone() * 32.expr(), pc.clone(), gas.clone()]),
        ));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        vec![("stack push".into(), stack_lookup)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (push_value, selector_index) = match trace.op {
            // get memory size from trace
            OpcodeId::MSIZE => (trace.memory.0.len().into(), 0),
            // get pc from trace
            OpcodeId::PC => (trace.pc.into(), 1),
            // get gas left from trace
            OpcodeId::GAS => ((trace.gas - OpcodeId::GAS.constant_gas_cost()).into(), 2),
            _ => panic!("opcode not match"),
        };
        assert_eq!(current_state.stack_top.unwrap_or_default(), push_value);

        let stack_push = current_state.get_push_stack_row(trace, push_value);

        // coew row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push]);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [TAG_IDX, TAG_IDX + 1, TAG_IDX + 2],
            selector_index,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        // core row 0
        let core_row_0 = ExecutionState::STATUS_INFO.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_push],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(StatusInfoGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn test_msize() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(65536)),
            memory_chunk: 2048u64,
            memory_chunk_prev: 2048u64,
            gas_left: 0x254023u64,
            ..WitnessExecHelper::new()
        };
        run(stack, current_state, OpcodeId::MSIZE)
    }

    #[test]
    fn test_pc() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(64)),
            gas_left: 0x254023u64,
            ..WitnessExecHelper::new()
        };
        run(stack, current_state, OpcodeId::PC)
    }

    #[test]
    fn test_gas() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(0x254023u64)),
            gas_left: 0x254023u64,
            ..WitnessExecHelper::new()
        };

        run(stack, current_state, OpcodeId::GAS)
    }

    #[test]
    fn test_msize_len_0() {
        let value = U256::from_big_endian(&[0x12; 32]);
        let stack = Stack::from_slice(&[value, 0xffff.into()]);
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        run(stack, current_state, OpcodeId::MSIZE);
    }

    fn run(stack: Stack, mut current_state: WitnessExecHelper, op: OpcodeId) {
        let mut trace = prepare_trace_step!(0, op, stack.clone());
        let stack_pointer = stack.0.len();

        let gas_left_before_exec = current_state.gas_left + op.constant_gas_cost();
        trace.gas = gas_left_before_exec;
        trace.pc = 64;

        if current_state.memory_chunk != 0 {
            let mut mem = Vec::new();
            mem.resize((current_state.memory_chunk * 32) as usize, 0);
            trace.memory.0 = mem;
        }

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row.pc = 64.into();
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 65.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
