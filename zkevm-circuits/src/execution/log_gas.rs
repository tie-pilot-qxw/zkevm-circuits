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
use gadgets::util::{pow_of_two, Expr};

use crate::arithmetic_circuit::operation;
use crate::constant::{GAS_LEFT_IDX, LENGTH_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY};
use crate::error::ExecError;
use crate::execution::ExecutionState::{END_CALL_1, LOG_TOPIC_NUM_ADDR};
use crate::execution::{
    end_call_1, log_topic_num_addr, memory_gas, Auxiliary, AuxiliaryOutcome,
    CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{convert_f_to_u256, query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 0;

const CORE_ROW_1_START_COL_IDX: usize = 7;
const LOG_GAS_NEXT_IS_LOG_TOPIC_NUM_ADDR: usize = 0;
const LOG_GAS_NEXT_IS_END_CALL_1: usize = 1;

/// log_gas 前一个指令为 memory_gas
/// 对应的opcode: LOG0, LOG1, LOG2, LOG3, LOG4
///
/// Table layout:
///     cnt = 1:
///         1. U64OVERFLOW is `gas_left u64 constraints`.
///         2. SELECTOR is opcode selector.
///         3. ISOVERFLOW check whether gas_left - gas_cost < 0 ,if true 1;else 0.
///         4. NIEC is 1 when next call is end_call_1
///         5. NILT is 1 when next call is log_topic_num_addr
/// +-----+--------------+--------------+-----------------------+
/// | cnt |              |              |                       |
/// +-----+--------------+--------------+-----------------------+
/// | 1   | U64OVERFLOW  | SELECTOR(7..11)  | ISOVERFLOW        |
/// | 0   | DYNAMIC(0..17) | AUX(18..24)|NILT|NIEC              |
/// +-----+--------------+--------------+-----------------------+

pub struct LogGasGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LogGasGadget<F>
{
    fn name(&self) -> &'static str {
        "LOG_GAS"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LOG_GAS
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW + memory_gas::NUM_ROW, log_topic_num_addr::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // current gas left is u64
        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let current_gas_left = meta.query_advice(gas_left, Rotation::cur());
        let gas_left_lt_gas_cost =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 5], Rotation::prev());
        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
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
                "(1 - gas_left_lt_gas_cost)* (gas_left_lo - current_gas_left) = 0".into(),
                (1.expr() - gas_left_lt_gas_cost.clone())
                    * (gas_left_lo.clone() - current_gas_left.clone()),
            ),
            (
                "gas_left_not_overflow is true".into(),
                1.expr() - gas_left_not_overflow.expr(),
            ),
        ]);

        // core constraints
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
                opcode.clone() - OpcodeId::LOG0.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG1.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG2.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG3.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG4.as_u8().expr(),
            ]),
        ));

        let memory_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );

        let length = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX],
            Rotation(-1 * NUM_ROW as i32 - 1 * memory_gas::NUM_ROW as i32),
        );

        let topic_gas = selector.select(&[0.expr(), 1.expr(), 2.expr(), 3.expr(), 4.expr()])
            * GasCost::LOG.expr();

        let gas_cost = memory_gas_cost
            + GasCost::LOG.expr()
            + topic_gas
            + length * GasCost::LOG_DATA_GAS.expr();
        // 在这里约束
        constraints.extend([(
            "gas_left < gas_cost, then gas_cost = current_gas_left + gas_left_lo".into(),
            gas_left_lt_gas_cost.clone()
                * (gas_cost.clone() - current_gas_left - gas_left_lo.clone()),
        )]);

        let gas_cost_delta = (1.expr() - gas_left_lt_gas_cost.clone()) * gas_cost;
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost_delta),
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
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        let next_call_is_log_topic = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + LOG_GAS_NEXT_IS_LOG_TOPIC_NUM_ADDR],
            Rotation::cur(),
        );
        let next_call_is_end_call_1 = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LOG_GAS_NEXT_IS_END_CALL_1],
            Rotation::cur(),
        );
        // 下一个状态是LOG_TOPIC_NUM_ADDR
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::MEMORY_GAS],
                NUM_ROW,
                vec![
                    (
                        LOG_TOPIC_NUM_ADDR,
                        log_topic_num_addr::NUM_ROW,
                        Some(next_call_is_log_topic),
                    ),
                    (
                        END_CALL_1,
                        end_call_1::NUM_ROW,
                        Some(next_call_is_end_call_1),
                    ),
                ],
                Some(vec![
                    1.expr() - gas_left_lt_gas_cost.clone(),
                    gas_left_lt_gas_cost.clone(),
                ]),
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let overflow = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });

        vec![("memory copier gas overflow".into(), overflow)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let tag_selector_index = match trace.op {
            OpcodeId::LOG0 => 0,
            OpcodeId::LOG1 => 1,
            OpcodeId::LOG2 => 2,
            OpcodeId::LOG3 => 3,
            OpcodeId::LOG4 => 4,
            _ => panic!("pure memory gas not supported opcode"),
        };
        let mut overflow_rows = vec![];

        let mut gas_left_lt_gas_cost = 0 as u64;
        match current_state.error {
            Some(ExecError::OutOfGas(..)) => {
                (overflow_rows, _) =
                    operation::u64overflow::gen_witness::<F>(vec![convert_f_to_u256(
                        &(F::from(trace.gas_cost) - F::from(current_state.gas_left)),
                    )]);
                gas_left_lt_gas_cost = 1;
            }
            _ => {
                (overflow_rows, _) = operation::u64overflow::gen_witness::<F>(vec![U256::from(
                    current_state.gas_left,
                )]);
            }
        };

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_arithmetic_tiny_lookup(0, &overflow_rows);
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
        // assign overflow flag
        assign_or_panic!(
            core_row_1[CORE_ROW_1_START_COL_IDX + 5],
            U256::from(gas_left_lt_gas_cost)
        );

        let mut core_row_0 = ExecutionState::LOG_GAS.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        if gas_left_lt_gas_cost == 0 {
            assign_or_panic!(
                core_row_0[NUM_STATE_HI_COL
                    + NUM_STATE_LO_COL
                    + NUM_AUXILIARY
                    + LOG_GAS_NEXT_IS_LOG_TOPIC_NUM_ADDR],
                U256::one()
            );
        } else {
            assign_or_panic!(
                core_row_0[NUM_STATE_HI_COL
                    + NUM_STATE_LO_COL
                    + NUM_AUXILIARY
                    + LOG_GAS_NEXT_IS_END_CALL_1],
                U256::one()
            );
        }

        let mut arithmetic = vec![];
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
    Box::new(LogGasGadget {
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
    fn assign_and_constraint(opcode: OpcodeId, stack: Stack, n: u64) {
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x0;
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            log_stamp,
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let length = stack.0.get(stack_pointer - 2).unwrap().as_u64();
        let gas_cost = GasCost::LOG + n * GasCost::LOG + length * GasCost::LOG_DATA_GAS;
        let gas_left_before_exec = current_state.gas_left + gas_cost;
        let mut trace = prepare_trace_step!(0, opcode, stack);
        trace.gas = gas_left_before_exec;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::MEMORY_GAS.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + LENGTH_IDX] =
                Some(length.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::LOG_TOPIC_NUM_ADDR.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
    #[test]
    fn test_log_bytes_log0() {
        let opcode = OpcodeId::LOG0;
        let stack = Stack::from_slice(&[0x4.into(), 0x1.into()]);
        assign_and_constraint(opcode, stack, 0)
    }

    #[test]
    fn test_log_bytes_log1() {
        let opcode = OpcodeId::LOG1;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(opcode, stack, 1)
    }
}
