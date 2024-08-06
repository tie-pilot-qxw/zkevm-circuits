// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

/// This module contains the implementation of the `AddmodGadget` struct, which is an execution gadget for the ADDMOD opcode in the EVM.
/// The `AddmodGadget` struct implements the `ExecutionGadget` trait and provides methods for generating constraints and witnesses for the ADDMOD opcode.
/// It also includes test cases for the `AddmodGadget` struct.
///
/// The ADDMOD opcode performs modular addition of two values and returns the result modulo a third value.
/// The ADDMOD opcode takes three inputs from the stack: a, b, and n.
/// It computes the sum of a and b modulo n and pushes the result back onto the stack.
/// The ADDMOD opcode modifies the stack pointer and the program counter.
///
/// The `AddmodGadget` struct uses lookup tables to perform the necessary state and arithmetic table lookups.
/// It also uses auxiliary outcomes to update the state stamp and stack pointer.
/// The `AddmodGadget` struct generates constraints and witnesses based on the given execution trace and current state.
///
use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;
const STACK_POINTER_DELTA: i32 = -2;
const PC_DELTA: u64 = 1;

pub struct AddmodGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Addmod Execution State layout is as follows
/// where STATE means state table lookup,
/// ARITH means arithmetic table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH  |      |       |          |
/// | 1 | STATE | STATE | STATE | STATE    |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for AddmodGadget<F>
{
    /// Returns the name of the execution circuit.
    fn name(&self) -> &'static str {
        "ADDMOD"
    }

    /// Returns the execution state of the circuit.
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ADDMOD
    }

    /// Returns the number of rows in the circuit.
    fn num_row(&self) -> usize {
        NUM_ROW
    }

    /// Returns the range of unusable rows in the circuit.
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }

    /// Returns the constraints for the execution circuit.
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // Retrieve the opcode advice from the meta cells.
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-OpcodeId::ADDMOD.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        // Get the auxiliary constraints.
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };

        // Get the core single-purpose constraints.
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        let mut arithmetic_operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            // i = 0, stack_pointer pop
            // i = 1, -1 pop
            // i = 2, -2 pop -1 - (i - 1)
            // i = 3, -2 push
            let stack_pointer_delta = if i == 0 {
                0
            } else if i == 1 {
                -1
            } else {
                -2
            };

            // Get the stack constraints.
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta.expr(),
                i == 3,
            ));

            // Extract the value_hi and value_lo from the state lookup expression.
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            arithmetic_operands.extend([value_hi, value_lo]);
        }

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        let (tag, arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));

        // Constraints for a, b, n, r
        constraints.extend((0..8).map(|i| {
            (
                format!("operand[{}] in arithmetic = in state lookup", i),
                arithmetic_operands[i].clone() - arithmetic_operands_full[i].clone(),
            )
        }));

        // Addmod constraints for opcode and arithmetic tag.
        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::ADDMOD.as_u8().expr()),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::Addmod as u8).expr(),
            ),
        ]);

        constraints
    }

    /// Returns the lookup entries for the execution circuit.
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // Query the stack lookups and arithmetic lookup from the meta cells.
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let stack_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));

        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack pop n".into(), stack_lookup_2),
            ("stack push".into(), stack_lookup_3),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }

    /// Generates the witness for the execution circuit.
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::ADDMOD);

        // Get the values for stack pop a, b, and n from the current state.
        let (stack_pop_a, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_b, b) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_n, n) = current_state.get_pop_stack_row_value(&trace);

        // Generate the witness for the addmod operation.
        let (arithmetic, result) = operation::addmod::gen_witness(vec![a, b, n]);
        assert_eq!(result[0], current_state.stack_top.unwrap());

        // Get the value for stack push from the current state.
        let stack_push = current_state.get_push_stack_row(trace, result[0]);

        // Get the core row 2 without the versatile columns.
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_pop_n, &stack_push]);

        // Get the core row 0 for the ADDMOD execution state.
        let core_row_0 = ExecutionState::ADDMOD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // return the witness
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_n, stack_pop_b, stack_pop_a, stack_push],
            arithmetic,
            ..Default::default()
        }
    }
}

/// Returns a new `AddmodGadget` execution gadget.
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(AddmodGadget {
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

    fn test_witness(stack: Stack, stack_pointer: usize, current_state: &mut WitnessExecHelper) {
        current_state.gas_left = 0x254023;
        let gas_left_before_exec = current_state.gas_left + OpcodeId::ADDMOD.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, OpcodeId::ADDMOD, stack);
        trace.gas = gas_left_before_exec;
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
            prepare_witness_and_prover!(trace, *current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    // Test the ADDMOD witness with a stack of usual values.
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[5.into(), 4.into(), 3.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(2.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }

    // Test the ADDMOD witness when divisor is zero.
    #[test]
    fn assign_and_constraint_zero() {
        let stack = Stack::from_slice(&[0.into(), 3.into(), 2.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }

    // Test the ADDMOD witness when a plus b is overflow.
    #[test]
    fn assign_and_constraint_overflow() {
        let stack = Stack::from_slice(&[2.into(), U256::MAX.into(), U256::MAX.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }

    #[test]
    fn assign_and_constraint_q_overflow() {
        let stack = Stack::from_slice(&[1.into(), U256::MAX.into(), U256::MAX.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }
}
