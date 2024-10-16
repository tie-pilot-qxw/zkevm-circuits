// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{self, get_lt_operations};
use crate::error::ExecError;
use crate::execution::{
    end_call_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{cal_valid_stack_pointer_range, query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, Witness, WitnessExecHelper};
use crate::witness::{assign_or_panic, fixed};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::ExecStateTransition;

const NUM_ROW: usize = 2;
const ERROR_STACK_TAG_OFFSET: usize = 7;
pub struct ErrorInvalidStackPointerGadget<E: Field> {
    _marker: PhantomData<E>,
}
/// Overview
///   Circuit constraints when stack pointer is out of range.
///   The stack pointer is out of range when it is less than the minimum stack pointer or greater than the maximum stack pointer.
///
/// Table Layout:
///     ARITH: u64 overflow arithmetic tiny lookup
///     FIXED0: ConstantGasCost fixed lookup
///     FIXED1: StackPointerRange fixed lookup
///     TAG: determines if the stack pointer is underflow or overflow
/// +---+-------+-------+-------+-------+
/// |cnt| 8 col | 8 col | 8 col | 8 col |
/// +---+-------+-------+-------+-------+
/// | 1 | | ARITH |TAG|   |FIXED0|FIXED1|
/// | 0 | DYNA_SELECTOR   | AUX         |
/// +---+-------+-------+-------+-------+

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ErrorInvalidStackPointerGadget<F>
{
    fn name(&self) -> &'static str {
        "ERROR_INVALID_STACK_POINTER"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ERROR_INVALID_STACK_POINTER
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, end_call_1::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // get stack_pointer cur
        let stack_pointer =
            meta.query_advice(config.get_auxiliary().stack_pointer, Rotation::cur());

        // get error_stack_tag
        // when error_stack_tag = 1, means stack underflow
        // when error_stack_tag = 0, means stack overflow
        let error_stack_tag =
            meta.query_advice(config.vers[ERROR_STACK_TAG_OFFSET], Rotation::prev());

        // constrain error_stack_tag must be 0 or 1
        constraints.push((
            "error_stack_tag must be 0 or 1".to_string(),
            error_stack_tag.clone() * (1.expr() - error_stack_tag.clone()),
        ));

        // get ConstantGasCost fixed lookup entry
        let (fixed_tag_0, [fixed_op_0, gas_cost, _]) =
            extract_lookup_expression!(fixed, config.get_fixed_lookup(meta, 0, Rotation::prev()));

        // get StackPointerRange fixed lookup entry
        let (fixed_tag_1, [fixed_op_1, min_stack_pointer, max_stack_pointer]) =
            extract_lookup_expression!(fixed, config.get_fixed_lookup(meta, 1, Rotation::prev()));

        // Extract the tag and arithmetic operands from the arithmetic lookup expression.
        let (arith_tag, [diff_hi, diff_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        );

        // Add constraints for lookup tag.
        constraints.extend([
            (
                "fixed tag 0".into(),
                fixed_tag_0 - (fixed::Tag::ConstantGasCost as u8).expr(),
            ),
            (
                "fixed tag 1".into(),
                fixed_tag_1 - (fixed::Tag::StackPointerRange as u8).expr(),
            ),
            (
                "arithmetic tag".into(),
                arith_tag - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
        ]);

        // constrain op from fixed lookup
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.extend([
            (
                "constrain fixed opcode 0".to_string(),
                fixed_op_0.clone() - opcode.clone(),
            ),
            (
                "constrain fixed opcode 1".to_string(),
                fixed_op_1.clone() - opcode.clone(),
            ),
        ]);

        // constraints diff_hi must be 0
        constraints.push(("diff_hi must be 0".into(), diff_hi.clone()));

        // constraints diff not overflow
        let not_overflow = SimpleIsZero::new(&overflow, &overflow_inv, "diff not overflow".into());
        constraints.push((
            "diff not overflow".to_string(),
            1.expr() - not_overflow.expr(),
        ));

        // get simple lt operand
        let left_operand = select::expr(
            error_stack_tag.clone(),
            stack_pointer.clone(),
            max_stack_pointer.clone(),
        );
        let right_operand = select::expr(
            error_stack_tag.clone(),
            min_stack_pointer.clone(),
            stack_pointer.clone(),
        );

        // constraints left_operand < right_operand
        let is_lt = SimpleLtGadget::<F, 8>::new(&left_operand, &right_operand, &1.expr(), &diff_lo);
        constraints.extend(is_lt.get_constraints());

        // next state is END_CALL_1
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::END_CALL_1, end_call_1::NUM_ROW, None)],
                None,
            ),
        ));

        // append the auxiliary constraints
        let auxiliary_delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(-gas_cost.clone()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta));

        // Append the core single-purpose constraints.
        constraints.append(
            &mut config
                .get_next_single_purpose_constraints(meta, CoreSinglePurposeOutcome::default()),
        );

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let arithmetic_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });
        let fixed_lookup_0 = query_expression(meta, |meta| {
            config.get_fixed_lookup(meta, 0, Rotation::prev())
        });
        let fixed_lookup_1 = query_expression(meta, |meta| {
            config.get_fixed_lookup(meta, 1, Rotation::prev())
        });

        vec![
            (
                "u64 overflow arithmetic_lookup lookup".into(),
                arithmetic_lookup,
            ),
            ("ConstantGasCost fixed lookup".into(), fixed_lookup_0),
            ("StackPointerRange fixed lookup".into(), fixed_lookup_1),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(matches!(
            current_state.error,
            Some(ExecError::StackOverflow | ExecError::StackUnderflow)
        ));

        current_state.return_success = false;

        let opcode = trace.op.clone();
        let stack_pointer = U256::from(trace.stack.0.len());

        // Get the stack pointer range for the opcode.
        let (min_stack_pointer, max_stack_pointer) = cal_valid_stack_pointer_range(&opcode);

        // Check if the stack pointer is out of range.
        assert!(
            stack_pointer < min_stack_pointer.into() || stack_pointer > max_stack_pointer.into()
        );

        // Check if the stack pointer is underflow(true) or overflow(false).
        let underflow = U256::from(min_stack_pointer) > stack_pointer;

        // row 0
        let core_row_0 = ExecutionState::ERROR_INVALID_STACK_POINTER.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        // get the sub arithmetic row
        let (_, diff, _) = if underflow {
            // stack_pointer < min_stack_pointer
            get_lt_operations(
                &stack_pointer,
                &min_stack_pointer.into(),
                &U256::from(2).pow(U256::from(64)),
            )
        } else {
            // max_stack_pointer < stack_pointer
            get_lt_operations(
                &max_stack_pointer.into(),
                &stack_pointer,
                &U256::from(2).pow(U256::from(64)),
            )
        };
        let (arithmetic, _) = operation::u64overflow::gen_witness::<F>(vec![diff]);

        core_row_1.insert_arithmetic_tiny_lookup(0, &arithmetic);
        core_row_1.insert_fixed_lookup_opcode(fixed::Tag::ConstantGasCost, opcode, 0);
        core_row_1.insert_fixed_lookup_opcode(fixed::Tag::StackPointerRange, opcode, 1);

        assign_or_panic!(
            core_row_1[ERROR_STACK_TAG_OFFSET],
            U256::from(underflow as u8)
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ErrorInvalidStackPointerGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::GAS_LEFT_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, op: OpcodeId, error: ExecError) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            gas_left: 0xffff,
            error: Some(error.clone()),
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(
            0,
            op,
            stack,
            Some(if error == ExecError::StackOverflow {
                "stack overflow".into()
            } else {
                "stack underflow".into()
            })
        );
        let gas_left_before_exec = current_state.gas_left + op.constant_gas_cost();
        trace.gas = gas_left_before_exec;
        trace.gas_cost = op.constant_gas_cost();

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());

            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = trace.pc.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_stack_underflow() {
        // stack.len() = 0
        // POP
        // STOP
        let stack = Stack::new();
        run(stack, OpcodeId::POP, ExecError::StackUnderflow);
    }

    #[test]
    fn test_stack_overflow() {
        // stack.len() = 1024
        // MSIZE
        // STOP
        let stack = Stack::from_vec(vec![U256::zero(); 1024]);
        run(stack, OpcodeId::MSIZE, ExecError::StackOverflow);
    }
}
