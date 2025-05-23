// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;

use crate::arithmetic_circuit::operation;
use crate::constant::{
    GAS_LEFT_IDX, LENGTH_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY, WARM_IDX,
};
use crate::execution::{
    memory_gas, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::{U64Div, U64Overflow};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

const PC_DELTA: usize = 1;
pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 0;

const CORE_ROW_1_START_COL_IDX: usize = 12;

/// memory_copier_gas 前一个指令为memory_gas
/// 对应的opcode: CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY
///
/// Table layout:
///     cnt = 1:
///         1. U64DIV is `(length_in_stack + 31) / 32`;
///         2. U64OVERFLOW is `gas_left u64 constraints`.
///         3. SELECTOR is opcode selector.
///
/// +-----+--------------+--------------+---------------------+
/// | cnt |              |              |                     |
/// +-----+--------------+--------------+---------------------+
/// | 1   | U64DIV       | U64OVERFLOW  | SELECTOR(12..15)    |
/// | 0   | DYNAMIC(0..17) | AUX(18..24)|                     |
/// +-----+--------------+--------------+---------------------+

pub struct MemoryCopierGasGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MemoryCopierGasGadget<F>
{
    fn name(&self) -> &'static str {
        "MEMORY_COPIER_GAS"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MEMORY_COPIER_GAS
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW + memory_gas::NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        let length = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX],
            Rotation(-1 * NUM_ROW as i32 - 1 * memory_gas::NUM_ROW as i32),
        );
        let (length_tag, [length_input, denominator, quotient, _]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        );
        constraints.extend([
            (
                "length tag is U64Div".into(),
                length_tag - (U64Div as u8).expr(),
            ),
            (
                "length_input == length + 31".into(),
                length_input - (length + 31.expr()),
            ),
            ("denominator == 32".into(), denominator - 32.expr()),
        ]);
        let memory_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );

        // current gas left is u64
        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let current_gas_left = meta.query_advice(gas_left, Rotation::cur());

        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 1, Rotation::prev())
        );
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left_u64_overflow".into());
        constraints.extend(gas_left_not_overflow.get_constraints());

        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            ("gas_left_hi == 0".into(), gas_left_hi.clone()),
            (
                "gas_left_lo = current_gas_left".into(),
                gas_left_lo - current_gas_left.clone(),
            ),
            (
                "gas_left not overflow".into(),
                1.expr() - gas_left_not_overflow.expr(),
            ),
        ]);

        // core constraints
        // 只用于计算extcodecopy
        // 其他opcode向上查找时不参与gas计算
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 3], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 4], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());
        constraints.push((
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::CALLDATACOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::CODECOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::RETURNDATACOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::EXTCODECOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::MCOPY.as_u8().expr(),
            ]),
        ));

        let warm_gas = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + WARM_IDX],
            Rotation(-1 * NUM_ROW as i32 - 1 * memory_gas::NUM_ROW as i32),
        );
        let base_gas = memory_gas_cost + quotient * GasCost::COPY.expr();
        let gas_cost = selector.select(&[
            base_gas.clone() + OpcodeId::CALLDATACOPY.constant_gas_cost().expr(),
            base_gas.clone() + OpcodeId::CODECOPY.constant_gas_cost().expr(),
            base_gas.clone() + OpcodeId::RETURNDATACOPY.constant_gas_cost().expr(),
            base_gas.clone() + warm_gas.clone(),
            base_gas.clone() + OpcodeId::MCOPY.constant_gas_cost().expr(),
        ]);

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            // 因为pc向后移动1，该指令下同一笔交易中其它状态不变
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::MEMORY_GAS], NUM_ROW, vec![], None),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let u64div = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });
        let overflow = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 1, Rotation::prev())
        });

        vec![
            ("memory copier gas u64div".into(), u64div),
            ("memory copier gas overflow".into(), overflow),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let tag_selector_index = match trace.op {
            OpcodeId::CALLDATACOPY => 0,
            OpcodeId::CODECOPY => 1,
            OpcodeId::RETURNDATACOPY => 2,
            OpcodeId::EXTCODECOPY => 3,
            OpcodeId::MCOPY => 4,
            _ => panic!("memory gas not supported opcode"),
        };

        let length = current_state.length_in_stack.unwrap();
        current_state.length_in_stack = None;
        let (length_row, _) =
            operation::u64div::gen_witness(vec![U256::from(length + 31), U256::from(32)]);

        let (overflow_rows, _) =
            operation::u64overflow::gen_witness::<F>(vec![U256::from(current_state.gas_left)]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_arithmetic_tiny_lookup(0, &length_row);
        core_row_1.insert_arithmetic_tiny_lookup(1, &overflow_rows);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
                CORE_ROW_1_START_COL_IDX + 3,
                CORE_ROW_1_START_COL_IDX + 4,
            ],
            tag_selector_index as usize,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::MEMORY_COPIER_GAS.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut arithmetic = vec![];
        arithmetic.extend(length_row);
        arithmetic.extend(overflow_rows);

        Witness {
            core: vec![core_row_1, core_row_0],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MemoryCopierGasGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::{LENGTH_IDX, MEMORY_CHUNK_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        //[length, src_offset, dst_offset]
        let length = 0x01u64;
        let stack = Stack::from_slice(&[length.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            memory_chunk: 1,
            memory_chunk_prev: 0,
            length_in_stack: Some(length),
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        let stack_pointer = stack.0.len();
        let mut trace = prepare_trace_step!(0, OpcodeId::CALLDATACOPY, stack);
        trace.gas = 0x3u64;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::MEMORY_GAS.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            // memory_chunk = 1
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + MEMORY_CHUNK_IDX] = Some(0x1.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX] =
                Some(length.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            // memory gas == 1(length_word) * 3 + constant(3)= 6
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(0x6.into());
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
        prover.assert_satisfied();
    }
}
