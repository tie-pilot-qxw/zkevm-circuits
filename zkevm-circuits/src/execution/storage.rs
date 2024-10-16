// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;
use crate::arithmetic_circuit::operation::{get_lt_operations, SLT_N_BYTES};
use crate::constant::{ARITHMETIC_TINY_COLUMN_WIDTH, ARITHMETIC_TINY_START_IDX};
use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::core::Row;
use crate::witness::{arithmetic, assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleDiffGadget;
use gadgets::util::{and, select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 5;

const STATE_STAMP_DELTA: u64 = 7;
const STACK_POINTER_DELTA_SLOAD: i32 = 0;
const STACK_POINTER_DELTA_SSTORE: i32 = -2;
const PC_DELTA: u64 = 1;

/// Storage is a combination of Sload and Sstore.
/// Algorithm overview:
/// SLOAD:
///     1. get key from stack
///     2. get value = storage[key]
///     3. write value to stack
/// SSTORE:
///     1. get key and value from stack
///     2. write value to storage[key]
/// Table layout:
/// SLOAD:
///     STATE1:  State lookup(call_context read storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack pop key), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  State lookup(storage read value), src: Core circuit, target: State circuit table, 8 columns
///     STATE4:  stack lookup(stack push value), src: Core circuit, target: State circuit table, 8 columns
/// SSTORE:
///     STATE1:  State lookup(call_context read storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack pop key), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  State lookup(stack pop value), src: Core circuit, target: State circuit table, 8 columns
///     STATE4:  stack lookup(storage write value), src: Core circuit, target: State circuit table, 8 columns
/// Public part:
///     STATE5:  State lookup(slot in access list read), src: Core circuit, target: State circuit table, 12 columns
///     STATE6:  State lookup(slot in access list write), src: Core circuit, target: State circuit table, 12 columns
///     STATE7:  State lookup(get_value_prev_storage_write_row), src: Core circuit, target: State circuit table, 12 columns
///     U64Overflow0: arithemetic tiny lookup, diff u64 constraint, src: Core circuit, target: Arithemetic circuit table, 5 columns
///     U64Overflow1: arithemetic tiny lookup, gas_left u64 constraint, src: Core circuit, target: Arithemetic circuit table, 5 columns
///     lt, diff: SstoreSentryGasEIP2200 < gas_left, lt constraint, 1 column
///     prev_eq_value_inv_hi: value_hi == value_pre_hi, 1 column
///     prev_eq_value_inv_lo: value_lo == value_pre_lo, 1 column
///     committed_eq_prev_inv_hi: committed_value_hi == value_pre_hi, 1 column
///     committed_eq_prev_inv_lo: committed_value_lo == value_pre_lo, 1 column
///     committed_value_inv: committed_value == 0, 1 column
///     value_inv: value == 0, 1 column
///     value_pre_inv: value_pre == 0, 1 column
///     committed_eq_value_inv_hi: committed_value_hi == value_hi, 1 column
///     committed_eq_value_inv_lo: committed_value_lo == value_lo, 1 column
///     cnt == 3, 21-30 columns is an intermediate variable needed to reduce degree
/// +-----+--------------------------------+----------------------------------+-----------------+------------------+------------------------+------------------------+----------------------------+----------------------------+-----------------------+-------------+-----------------+-----------------------------+-----------------------------+--------------------+------------------------------+-------------------------------+------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
/// | cnt |                                |                                |                 |                  |                        |                        |                            |                            |                       |             |                 |                             |                             |                    |                              |                               |            |                 |                 |                 |                 |                 |                 |
/// +-----+--------------------------------+----------------------------------+-----------------+------------------+------------------------+------------------------+----------------------------+----------------------------+-----------------------+-------------+-----------------+-----------------------------+-----------------------------+--------------------+------------------------------+-------------------------------+------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
/// | 4   | STATE7(0..11)                  |                                |                 |                  |                        |                        |                            |                            |                       |             |                 |                             |                             |                    |                              |                               |            |                 |                 |                 |                 |                 |                 |
/// | 3   | STATE5(0..11)                  | STATE6(12..23)                  |                 |                  |                        |                        |                            |                            |                       |             |                 |                             |                             |                    |                              |                               |            |                 |                 |                 |                 |                 |                 |
/// | 2   | lt(0)                          | diff(1)                        | U64Overflow0(2..6) | U64Overflow1(7..11) | prev_eq_value_inv_hi(12) | prev_eq_value_inv_lo(13) | committed_eq_prev_inv_hi(14) | committed_eq_prev_inv_lo(15) | committed_value_inv(16) | value_inv(17) | value_pre_inv(18) | committed_eq_value_inv_hi(19) | committed_eq_value_inv_lo(20) | value_is_eq_prev(21) | committed_value_is_eq_prev(22) | committed_value_is_eq_value(23) | slot_gas(24) | warm_case_gas(25) | refund_part_1(26) | refund_part_2(27) | refund_part_3(28) | refund_part_4(29) | refund_part_5(30) |
/// | 1   | STATE1(0..7)                   | STATE2(8..15)                  | STATE3(16..23)  | STATE4(24..31)   |                        |                        |                            |                            |                       |             |                 |                             |                             |                    |                              |                               |            |                 |                 |                 |                 |                 |                 |
/// | 0   | dynamic_selector(0..17)        | AUX(18..24)                    |                 |                  |                        |                        |                            |                            |                       |             |                 |                             |                             |                    |                              |                               |            |                 |                 |                 |                 |                 |                 |
/// +-----+--------------------------------+----------------------------------+-----------------+------------------+------------------------+------------------------+----------------------------+----------------------------+-----------------------+-------------+-----------------+-----------------------------+-----------------------------+--------------------+------------------------------+-------------------------------+------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
/// Note:
///     1. In STATE3 of SLOAD and STATE4 of SSTORE, contract_addr is value hi,lo of STATE1 and pointer hi,lo is value hi,lo of STATE2.
///     2. STATE4's value hi,lo equals to value hi,lo of STATE3
pub struct StorageGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for StorageGadget<F>
{
    fn name(&self) -> &'static str {
        "STORAGE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STORAGE
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
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        // append stack constraints, call_context constraints and storage constrains
        let mut operands: Vec<[Expression<F>; 2]> = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);

            if i == 0 {
                let call_id = meta.query_advice(config.call_id, Rotation::cur());
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    (state::CallContextTag::StorageContractAddr as u8).expr(),
                    call_id,
                ));
            } else if i == 1 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    0.expr(),
                    false,
                ));
            } else {
                constraints.append(&mut config.get_storage_constraints_with_selector(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    operands[0][0].clone(),
                    operands[0][1].clone(),
                    operands[1][0].clone(),
                    operands[1][1].clone(),
                    if i == 2 { false } else { true },
                    if i == 2 {
                        OpcodeId::SSTORE.as_u8().expr() - opcode.clone()
                    } else {
                        opcode.clone() - OpcodeId::SLOAD.as_u8().expr()
                    }, //enable the constraints when i == 2, opcode == SLOAD or i == 3, opcode == SSTORE
                ));
                constraints.append(&mut config.get_stack_constraints_with_selector(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    if i == 2 { (-1).expr() } else { 0.expr() },
                    if i == 2 { false } else { true },
                    if i == 2 {
                        opcode.clone() - OpcodeId::SLOAD.as_u8().expr()
                    } else {
                        OpcodeId::SSTORE.as_u8().expr() - opcode.clone()
                    }, //enable the constraints when i == 2, opcode == SSTORE or i == 3, opcode == SLOAD
                ));
            }
            let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let (storage_gas_cal, build_constraints) =
            StorageGasCost::build(config, operands.clone(), meta);
        let sload_gas_cost = storage_gas_cal.sload_gas_cost();
        let (sstore_gas_cost, sstore_gas_cost_constraints) =
            storage_gas_cal.sstore_gas_cost(config, meta);
        let (sstore_tx_refund, tx_refund_constraints) =
            storage_gas_cal.sstore_tx_refund(config, meta);

        constraints.extend(build_constraints);
        constraints.extend(sstore_gas_cost_constraints);
        constraints.extend(tx_refund_constraints);
        // append auxiliary constraints
        let is_sload = OpcodeId::SSTORE.as_u8().expr() - opcode.clone();
        let is_sstore = opcode.clone() - OpcodeId::SLOAD.as_u8().expr();

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(
                STACK_POINTER_DELTA_SLOAD.expr() * is_sload.clone()
                    + STACK_POINTER_DELTA_SSTORE.expr() * is_sstore.clone(),
            ), //the property OpcodeId::SSTORE - OpcodeId::SLOAD == 1 is used
            // before degree 16
            // now degree max 9
            gas_left: ExpressionOutcome::Delta(
                -sload_gas_cost.clone() * is_sload.clone()
                    - sstore_gas_cost.clone() * is_sstore.clone(),
            ),
            // before degree 14
            // now degree max 9
            refund: ExpressionOutcome::Delta(is_sstore.clone() * sstore_tx_refund.clone()),
            ..Default::default()
        };

        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // option: 1. is_warm read and write
        let storage_read_stack_pop = operands[2].clone();
        let stack_push_storage_write = operands[3].clone();
        // append constraints for state_lookup's values
        constraints.extend([
            (
                "storage_read == stack_push or stack_pop == storage_write hi".into(),
                storage_read_stack_pop[0].clone() - stack_push_storage_write[0].clone(),
            ),
            (
                "storage_read == stack_push or stack_pop == storage_write lo".into(),
                storage_read_stack_pop[1].clone() - stack_push_storage_write[1].clone(),
            ),
        ]);
        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            (opcode.clone() - OpcodeId::SLOAD.expr()) * (opcode - OpcodeId::SSTORE.expr()),
        )]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        // must 2. gas_left u64 overflow
        // gas_left u64 overflow, 这个约束就保证了gas_left_before_exec - gas_cost > 0
        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let gas_left = meta.query_advice(gas_left, Rotation::cur());
        let (tag, [value_hi, value_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 1));
        let not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left u64 overflow".into());
        constraints.extend(not_overflow.get_constraints());
        constraints.extend([
            (
                "arithmetic tag is u64".into(),
                tag - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
            ("value_hi in arithmetic == 0".into(), value_hi),
            (
                "gas_left_lo == value_lo in arithmetic".into(),
                gas_left - value_lo,
            ),
            (
                "gas_left not overflow".into(),
                1.expr() - not_overflow.expr(),
            ),
        ]);

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let storage_contract_addr_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let storage_or_stack_lookup_0 =
            query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let storage_or_stack_lookup_1 =
            query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        // option: 1. is_warm read and write lookup
        let slot_storage_read = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-3))
        });
        let slot_storage_write = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-3))
        });
        let diff_overflow_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        // must: 3. gas_left u64 overflow lookup
        let arithmetic_u64overflow_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 1));
        let value_prev_lookup = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-4))
        });
        vec![
            ("StorageContractAddr".into(), storage_contract_addr_lookup),
            ("stack pop".into(), stack_lookup),
            (
                "storage read or stack pop".into(),
                storage_or_stack_lookup_0,
            ),
            (
                "stack push or storage write".into(),
                storage_or_stack_lookup_1,
            ),
            ("slot storage read".into(), slot_storage_read),
            ("slot storage write".into(), slot_storage_write),
            ("diff u64 overflow".into(), diff_overflow_lookup),
            (
                "arithmetic u64 overflow".into(),
                arithmetic_u64overflow_lookup,
            ),
            ("value prev lookup".into(), value_prev_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::SLOAD || trace.op == OpcodeId::SSTORE);
        //generate storage_contract_addr read row
        let (storage_contract_addr_row, storage_contract_addr) =
            current_state.get_storage_contract_addr_row();
        //generate storage pop key row
        let (stack_pop_row, storage_key) = current_state.get_pop_stack_row_value(&trace);

        //generate storage read row and stack push value row (for SLOAD) or stack pop value row and storage write row (for SSTORE)
        let (storage_or_stack_0, storage_or_stack_1, storage_value) = if trace.op == OpcodeId::SLOAD
        {
            let (storage_or_stack_0, value) = current_state.get_storage_read_row_value(
                &trace,
                storage_key,
                storage_contract_addr,
            );
            let storage_or_stack_1 = current_state.get_push_stack_row(&trace, value);
            (storage_or_stack_0, storage_or_stack_1, value)
        } else {
            let (storage_or_stack_0, value) = current_state.get_pop_stack_row_value(&trace);
            let storage_or_stack_1 =
                current_state.get_storage_write_row(storage_key, value, storage_contract_addr);
            (storage_or_stack_0, storage_or_stack_1, value)
        };
        //generate core row
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &storage_contract_addr_row,
            &stack_pop_row,
            &storage_or_stack_0,
            &storage_or_stack_1,
        ]);

        let (core_row_2, arithmetic) = get_core_row_2::<F>(
            trace,
            current_state,
            storage_key,
            storage_value,
            storage_contract_addr,
        );

        let (core_row_3, is_warm_rows) =
            get_core_row_3(trace, current_state, storage_key, storage_contract_addr);

        let (core_row_4, storage_rows) = get_core_row_4(
            trace,
            current_state,
            storage_key,
            storage_value,
            storage_contract_addr,
        );

        let core_row_0 = ExecutionState::STORAGE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        if trace.op == OpcodeId::SSTORE {
            current_state.insert_dirty_storage(storage_contract_addr, storage_key, storage_value);
        }

        let mut state = vec![
            storage_contract_addr_row,
            stack_pop_row,
            storage_or_stack_0,
            storage_or_stack_1,
        ];
        state.extend(is_warm_rows);
        state.extend(storage_rows);

        Witness {
            core: vec![core_row_4, core_row_3, core_row_2, core_row_1, core_row_0],
            state,
            arithmetic,
            ..Default::default()
        }
    }
}

fn get_core_row_2<F: Field>(
    trace: &GethExecStep,
    current_state: &mut WitnessExecHelper,
    storage_key: U256,
    storage_value: U256,
    contract_addr: U256,
) -> (Row, Vec<arithmetic::Row>) {
    let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

    // 1.我们需要SstoreSentryGasEIP2200 < gas_left_before_exec，trace.gas == gas_left_before_exec
    // 如果用memory_expansion， 传参为[GasCost::SSTORE_SENTRY * 32, trace.gas]，
    // 此时我们约束lt == 0，是包含了trace.gas == GasCost::SSTORE_SENTRY的情况，这在EVM里是Error；
    // 如果传参改为[trace.gas * 32, GasCost::SSTORE_SENTRY]，没办法保证trace.gas * 32后是U64的；
    // 解决方法应该是 SimpleDiffGadget + diff U64OVERFLOW
    let (lt, diff, ..) = get_lt_operations(
        &U256::from(GasCost::SSTORE_SENTRY),
        &U256::from(trace.gas),
        &U256::from(2).pow(U256::from(SLT_N_BYTES * 32)),
    );
    core_row_2[0] = Some((lt as u8).into());
    core_row_2[1] = Some(diff);
    let (mut diff_overflow_row, res) = operation::u64overflow::gen_witness::<F>(vec![diff]);
    assert!(res[0].is_zero());

    // 2,gas_left_after_exec < 2^64
    // current_state.gas_left == gas_left_after_exec
    let (arith_row, _) =
        operation::u64overflow::gen_witness::<F>(vec![current_state.gas_left.into()]);
    core_row_2.insert_arithmetic_tiny_lookup(0, &diff_overflow_row);
    core_row_2.insert_arithmetic_tiny_lookup(1, &arith_row);
    diff_overflow_row.extend(arith_row);

    // 3. Insert intermediate variables required for gas calculation
    let (_, value_prev) =
        current_state.get_dirty_value(&contract_addr, &storage_key, current_state.tx_idx);
    let (_, committed_value) =
        current_state.get_committed_value(&contract_addr, &storage_key, current_state.tx_idx);

    let value_prev_hi = value_prev >> 128;
    let value_prev_lo = U256::from(value_prev.low_u128());
    let committed_value_hi = committed_value >> 128;
    let committed_value_lo = U256::from(committed_value.low_u128());
    let storage_value_hi = storage_value >> 128;
    let storage_value_lo = U256::from(storage_value.low_u128());

    // 3.1. value_prev == value
    let prev_eq_value_inv_hi = get_diff_inv::<F>(&value_prev_hi, &storage_value_hi);
    let prev_eq_value_inv_lo = get_diff_inv::<F>(&value_prev_lo, &storage_value_lo);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX],
        prev_eq_value_inv_hi
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 1],
        prev_eq_value_inv_lo
    );

    // 3.2.committed_value == value_prev
    let committed_eq_prev_inv_hi = get_diff_inv::<F>(&committed_value_hi, &value_prev_hi);
    let committed_eq_prev_inv_lo = get_diff_inv::<F>(&committed_value_lo, &value_prev_lo);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 2],
        committed_eq_prev_inv_hi
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 3],
        committed_eq_prev_inv_lo
    );

    // 3.3.committed_value =? 0
    let committed_value_inv = get_multi_inverse::<F>(committed_value);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 4],
        committed_value_inv
    );

    // 3.4. value_is_zero
    let value_inv = get_multi_inverse::<F>(storage_value);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 5],
        value_inv
    );

    // 3.5. value_pre_is_zero
    let value_pre_inv = get_multi_inverse::<F>(value_prev);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 6],
        value_pre_inv
    );

    // 3.6. committed_eq_value
    let committed_eq_value_inv_hi = get_diff_inv::<F>(&committed_value_hi, &storage_value_hi);
    let committed_eq_value_inv_lo = get_diff_inv::<F>(&committed_value_lo, &storage_value_lo);
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 7],
        committed_eq_value_inv_hi
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 8],
        committed_eq_value_inv_lo
    );

    // 4.1 lower degree -- gas
    let value_is_eq_prev = storage_value == value_prev;
    let committed_value_is_eq_prev = committed_value == value_prev;
    let committed_value_is_eq_value = committed_value == storage_value;
    let slot_gas = if committed_value_is_eq_prev {
        if committed_value == U256::zero() {
            GasCost::SSTORE_SET
        } else {
            GasCost::SSTORE_RESET
        }
    } else {
        GasCost::WARM_ACCESS
    };
    let warm_case_gas = if value_is_eq_prev {
        GasCost::WARM_ACCESS
    } else {
        slot_gas
    };
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 9],
        U256::from(value_is_eq_prev as u8)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 10],
        U256::from(committed_value_is_eq_prev as u8)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 11],
        U256::from(committed_value_is_eq_value as u8)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 12],
        U256::from(slot_gas)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 13],
        U256::from(warm_case_gas)
    );

    // 4.2 lower degree -- refund
    let refund_part_1 = (1 - (committed_value == U256::zero()) as u64)
        * ((value_prev == U256::zero()) as u64)
        * GasCost::SSTORE_CLEARS_SCHEDULE;
    let refund_part_2 = (1 - (committed_value == U256::zero()) as u64)
        * ((storage_value == U256::zero()) as u64)
        * GasCost::SSTORE_CLEARS_SCHEDULE;
    let refund_part_3 = (committed_value_is_eq_value as u64)
        * ((committed_value == U256::zero()) as u64)
        * (GasCost::SSTORE_SET - GasCost::WARM_ACCESS);
    let refund_part_4 = (committed_value_is_eq_value as u64)
        * (1 - (committed_value == U256::zero()) as u64)
        * (GasCost::SSTORE_RESET - GasCost::WARM_ACCESS);
    let refund_part_5 = committed_value_is_eq_prev && (storage_value == U256::zero());

    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 14],
        U256::from(refund_part_1)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 15],
        U256::from(refund_part_2)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 16],
        U256::from(refund_part_3)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 17],
        U256::from(refund_part_4)
    );
    assign_or_panic!(
        core_row_2[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 18],
        U256::from(refund_part_5 as u8)
    );

    (core_row_2, diff_overflow_row)
}

fn get_core_row_3(
    trace: &GethExecStep,
    current_state: &mut WitnessExecHelper,
    storage_key: U256,
    contract_addr: U256,
) -> (Row, Vec<state::Row>) {
    let mut core_row_3 = current_state.get_core_row_without_versatile(&trace, 3);
    let (is_warm_read_row, is_warm) =
        current_state.get_slot_access_list_read_row(contract_addr, storage_key);
    // 需要把is_warm置为true，相当于往storage中写一个值进去
    let is_warm_write_row =
        current_state.get_slot_access_list_write_row(contract_addr, storage_key, true, is_warm);
    core_row_3.insert_storage_lookups([&is_warm_read_row, &is_warm_write_row]);

    (core_row_3, vec![is_warm_read_row, is_warm_write_row])
}

fn get_core_row_4(
    trace: &GethExecStep,
    current_state: &mut WitnessExecHelper,
    storage_key: U256,
    storage_value: U256,
    contract_addr: U256,
) -> (Row, Vec<state::Row>) {
    let (_, value_prev) =
        current_state.get_dirty_value(&contract_addr, &storage_key, current_state.tx_idx);
    let (_, committed_value) =
        current_state.get_committed_value(&contract_addr, &storage_key, current_state.tx_idx);

    let mut core_row_4 = current_state.get_core_row_without_versatile(&trace, 4);
    let storage_write_row = current_state.get_storage_full_write_row(
        storage_key,
        storage_value,
        contract_addr,
        value_prev,
        committed_value,
    );
    core_row_4.insert_storage_lookups([&storage_write_row]);

    (core_row_4, vec![storage_write_row])
}

struct StorageGasCost<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> {
    value_eq_prev: Expression<F>,
    is_warm: Expression<F>,
    committed_eq_prev: Expression<F>,
    committed_is_zero: Expression<F>,
    value_is_zero: Expression<F>,
    value_pre_is_zero: Expression<F>,
    committed_eq_value: Expression<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    StorageGasCost<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    fn build(
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        operands: Vec<[Expression<F>; 2]>,
        meta: &mut VirtualCells<F>,
    ) -> (Self, Vec<(String, Expression<F>)>) {
        let mut values: Vec<[Expression<F>; 2]> = vec![];
        let mut constraints = vec![];

        let lookups = [
            (
                0,
                Rotation(-3),
                4,
                false,
                state::Tag::SlotInAccessListStorage,
            ), // is_warm read
            (
                1,
                Rotation(-3),
                5,
                true,
                state::Tag::SlotInAccessListStorage,
            ), // is_warm write
            (0, Rotation(-4), 6, true, state::Tag::Storage), // storage_full
        ];

        for &(num, rotation, index, is_write, tag) in &lookups {
            let entry = config.get_storage_lookup(meta, num, rotation);
            constraints.extend(config.get_storage_full_constraints_with_tag(
                meta,
                entry.clone(),
                index,
                NUM_ROW,
                operands[0][0].clone(),
                operands[0][1].clone(),
                operands[1][0].clone(),
                operands[1][1].clone(),
                tag,
                is_write,
            ));
            let extracted = extract_lookup_expression!(storage, entry);
            if index == 4 {
                values.push([extracted.2.clone(), extracted.3.clone()]); // 00, 01 is_warm
            }
            if index == 6 {
                values.push([extracted.2.clone(), extracted.3.clone()]); // 10-value_hi, 11-value_lo
                values.push([extracted.8.clone(), extracted.9.clone()]); // 20-value_pre_hi, 21-value_pre_lo
                values.push([extracted.10.clone(), extracted.11.clone()]); // 30-committed_value_hi, 31-committed_value_lo,
            }
        }

        let prev_eq_value_inv_hi = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX],
            Rotation(-2),
        );
        let prev_eq_value_inv_lo = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 1],
            Rotation(-2),
        );
        let committed_eq_prev_inv_hi = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 2],
            Rotation(-2),
        );
        let committed_eq_prev_inv_lo = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 3],
            Rotation(-2),
        );
        let committed_value_inv = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 4],
            Rotation(-2),
        );

        let value_inv = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 5],
            Rotation(-2),
        );
        let value_pre_inv = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 6],
            Rotation(-2),
        );
        let committed_eq_value_inv_hi = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 7],
            Rotation(-2),
        );
        let committed_eq_value_inv_lo = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 8],
            Rotation(-2),
        );

        // 2. value_prev == value
        let is_zero_hi = SimpleIsZero::new(
            &(values[2][0].clone() - values[1][0].clone()),
            &prev_eq_value_inv_hi,
            "value_eq_prev_hi".into(),
        );
        constraints.extend(is_zero_hi.get_constraints());

        let is_zero_lo = SimpleIsZero::new(
            &(values[2][1].clone() - values[1][1].clone()),
            &prev_eq_value_inv_lo,
            "value_eq_prev_lo".into(),
        );
        constraints.extend(is_zero_lo.get_constraints());

        let value_eq_prev = and::expr([is_zero_hi.expr(), is_zero_lo.expr()]);
        let value_is_eq_prev = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 9],
            Rotation(-2),
        );

        constraints.push((
            "value_is_eq_prev == is_zero_hi * is_zero_lo".into(),
            value_is_eq_prev.clone() - value_eq_prev.clone(),
        ));

        // 5.committed_value == value_prev
        let is_zero_hi = SimpleIsZero::new(
            &(values[3][0].clone() - values[2][0].clone()),
            &committed_eq_prev_inv_hi,
            "committed_eq_prev_hi".into(),
        );
        constraints.extend(is_zero_hi.get_constraints());

        let is_zero_lo = SimpleIsZero::new(
            &(values[3][1].clone() - values[2][1].clone()),
            &committed_eq_prev_inv_lo,
            "committed_eq_prev_lo".into(),
        );
        constraints.extend(is_zero_lo.get_constraints());

        // degree 9
        let committed_eq_prev = and::expr([is_zero_hi.expr(), is_zero_lo.expr()]);
        let committed_value_is_eq_prev = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 10],
            Rotation(-2),
        );

        constraints.push((
            "committed_eq_prev == is_zero_hi * is_zero_lo".into(),
            committed_value_is_eq_prev.clone() - committed_eq_prev.clone(),
        ));

        // 6.committed_value =? 0
        let committed_is_zero = SimpleIsZero::new(
            &(values[3][0].clone() + values[3][1].clone()),
            &committed_value_inv,
            "committed_eq_zero".into(),
        );
        constraints.extend(committed_is_zero.get_constraints());

        // 7.value == 0
        let value_is_zero = SimpleIsZero::new(
            &(values[1][0].clone() + values[1][1].clone()),
            &value_inv,
            "value_is_zero".into(),
        );
        constraints.extend(value_is_zero.get_constraints());

        // 8. value_pre == 0
        let value_pre_is_zero = SimpleIsZero::new(
            &(values[2][0].clone() + values[2][1].clone()),
            &value_pre_inv,
            "value_pre_is_zero".into(),
        );
        constraints.extend(value_pre_is_zero.get_constraints());

        // 9. committed_value == value
        let is_zero_hi = SimpleIsZero::new(
            &(values[3][0].clone() - values[1][0].clone()),
            &committed_eq_value_inv_hi,
            "committed_eq_value_hi".into(),
        );
        constraints.extend(is_zero_hi.get_constraints());

        let is_zero_lo = SimpleIsZero::new(
            &(values[3][1].clone() - values[1][1].clone()),
            &committed_eq_value_inv_lo,
            "committed_eq_value_lo".into(),
        );
        constraints.extend(is_zero_lo.get_constraints());

        let committed_eq_value = and::expr([is_zero_hi.expr(), is_zero_lo.expr()]);
        let committed_value_is_eq_value = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 11],
            Rotation(-2),
        );

        constraints.push((
            "committed_value_is_eq_value == is_zero_hi * is_zero_lo".into(),
            committed_value_is_eq_value.clone() - committed_eq_value.clone(),
        ));

        (
            Self {
                value_eq_prev: value_is_eq_prev,
                committed_eq_prev: committed_value_is_eq_prev,
                committed_eq_value: committed_value_is_eq_value,
                is_warm: values[0][1].expr(),
                committed_is_zero: committed_is_zero.expr(),
                value_is_zero: value_is_zero.expr(),
                value_pre_is_zero: value_pre_is_zero.expr(),
            },
            constraints,
        )
    }

    /// 1.warm case select:
    /// if value = value_pre {
    ///    return WARM_ACCESS (100)
    /// }else{
    ///     if commit_value = value_pre {
    ///        if commit_value = 0 {
    ///             return SSTORE_SET (20000)
    ///         }else {
    ///             return SSTORE_RESET (2900)
    ///         }
    ///     }else{
    ///         return WARM_ACCESS（100）
    ///     }
    /// }
    ///
    /// 2,cold case select:
    /// if is_warm {
    ///     return warm_case_gas
    /// }else{
    ///     return warm_case_gas + COLD_SLOAD (2100)
    /// }
    fn sstore_gas_cost(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> (Expression<F>, Vec<(String, Expression<F>)>) {
        // 1. SstoreSentryGasEIP2200 < gas_left
        let lt = meta.query_advice(config.vers[0], Rotation(-2));
        let diff = meta.query_advice(config.vers[1], Rotation(-2));
        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let gas_left = meta.query_advice(gas_left, Rotation(-1 * NUM_ROW as i32));
        let is_lt: SimpleDiffGadget<F, 8> = SimpleDiffGadget::new(
            &GasCost::SSTORE_SENTRY.expr(),
            &gas_left,
            &lt,
            &diff.clone(),
        );
        let mut constraints = is_lt.get_constraints();
        constraints.push(("SSTORE_SENTRY < gas_left".into(), 1.expr() - is_lt.expr()));

        let (tag, [value_hi, value_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));
        let not_overflow = SimpleIsZero::new(&overflow, &overflow_inv, "diff u64 overflow".into());
        constraints.extend(not_overflow.get_constraints());
        constraints.extend([
            (
                "arithmetic tag is u64".into(),
                tag - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
            ("diff value_hi in arithmetic == 0".into(), value_hi),
            ("diff == value_lo in arithmetic".into(), diff - value_lo),
            ("diff not overflow".into(), 1.expr() - not_overflow.expr()),
        ]);

        // 2.gas_cost
        let set_slot_gas = select::expr(
            self.committed_eq_prev.clone(),
            select::expr(
                self.committed_is_zero.clone(),
                GasCost::SSTORE_SET.expr(),
                GasCost::SSTORE_RESET.expr(),
            ),
            GasCost::WARM_ACCESS.expr(),
        );

        let slot_gas = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 12],
            Rotation(-2),
        );

        constraints.push((
            "slot gas constraint".into(),
            set_slot_gas.clone() - slot_gas.clone(),
        ));

        let warm_case_gas = select::expr(
            self.value_eq_prev.clone(),
            GasCost::WARM_ACCESS.expr(),
            slot_gas,
        );

        let warm_gas = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 13],
            Rotation(-2),
        );

        constraints.push((
            "warm case gas constraint".into(),
            warm_case_gas.clone() - warm_gas.clone(),
        ));

        (
            select::expr(
                self.is_warm.clone(),
                warm_gas.clone(),
                warm_gas + GasCost::COLD_SLOAD.expr(),
            ),
            constraints,
        )
    }

    /// The refund in this round is a delta value, not the final refund
    /// if current != value {
    ///     if commit == value_prev && value == 0 {
    ///         cost + SstoreClearsScheduleRefundEIP3529(4800)
    ///     } else {
    ///         if commit != 0 && value_prev == 0 {
    ///             cost - SstoreClearsScheduleRefundEIP3529(4800) -- refund_part_1
    ///         }
    ///         if commit != 0 && value == 0 {
    ///             cost + SstoreClearsScheduleRefundEIP3529(4800) -- refund_part_2
    ///         }
    ///         if commit == value && commit == 0 {
    ///             cost + SstoreSetGasEIP2200（20000）- WarmStorageReadCostEIP2929（100）-- refund_part_3
    ///         }
    ///         if commit == value && commit != 0 {
    ///             cost + SstoreResetGasEIP2200（5000）-ColdSloadCostEIP2929（2100） - WarmStorageReadCostEIP2929（100）-- refund_part_4
    ///         }
    ///     }
    /// }

    fn sstore_tx_refund(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> (Expression<F>, Vec<(String, Expression<F>)>) {
        let mut constraints = vec![];
        // 1. commit != 0 && value_pre == 0
        let refund_part_1 = (1.expr() - self.committed_is_zero.clone())
            * self.value_pre_is_zero.clone()
            * GasCost::SSTORE_CLEARS_SCHEDULE.expr();

        let query_refund_part_1 = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 14],
            Rotation(-2),
        );
        constraints.push((
            "refund_part_1".into(),
            refund_part_1.clone() - query_refund_part_1.clone(),
        ));

        // 2. commit != 0 && value == 0
        let refund_part_2 = (1.expr() - self.committed_is_zero.clone())
            * self.value_is_zero.clone()
            * GasCost::SSTORE_CLEARS_SCHEDULE.expr();

        let query_refund_part_2 = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 15],
            Rotation(-2),
        );
        constraints.push((
            "refund_part_2".into(),
            refund_part_2.clone() - query_refund_part_2.clone(),
        ));

        // 3. commit == value && commit == 0
        let refund_part_3 = self.committed_eq_value.clone()
            * self.committed_is_zero.clone()
            * (GasCost::SSTORE_SET.expr() - GasCost::WARM_ACCESS.expr());

        let query_refund_part_3 = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 16],
            Rotation(-2),
        );
        constraints.push((
            "refund_part_3".into(),
            refund_part_3.clone() - query_refund_part_3.clone(),
        ));

        // 4. commit == value && commit != 0
        let refund_part_4 = self.committed_eq_value.clone()
            * (1.expr() - self.committed_is_zero.clone())
            * (GasCost::SSTORE_RESET.expr() - GasCost::WARM_ACCESS.expr());

        let query_refund_part_4 = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 17],
            Rotation(-2),
        );
        constraints.push((
            "refund_part_4".into(),
            refund_part_4.clone() - query_refund_part_4.clone(),
        ));

        // 5. commit == prev && value == 0
        let refund_part_5 = self.committed_eq_prev.clone() * self.value_is_zero.clone();

        let query_refund_part_5 = meta.query_advice(
            config.vers[2 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 18],
            Rotation(-2),
        );
        constraints.push((
            "refund_part_5".into(),
            refund_part_5.clone() - query_refund_part_5.clone(),
        ));

        (
            select::expr(
                self.value_eq_prev.clone(),
                0.expr(),
                select::expr(
                    query_refund_part_5,
                    GasCost::SSTORE_CLEARS_SCHEDULE.expr(),
                    -query_refund_part_1
                        + query_refund_part_2
                        + query_refund_part_3
                        + query_refund_part_4,
                ),
            ),
            constraints,
        )
    }

    // sload not tx_refund
    fn sload_gas_cost(&self) -> Expression<F> {
        select::expr(
            self.is_warm.clone(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_SLOAD.expr(),
        )
    }
}

// lhs, rhs is 128bit
fn get_diff_inv<F: Field>(lhs: &U256, rhs: &U256) -> U256 {
    let lhs = F::from_u128(lhs.as_u128());
    let rhs = F::from_u128(rhs.as_u128());

    let eq = (lhs - rhs).invert().unwrap_or(F::ZERO);

    U256::from_little_endian(eq.to_repr().as_ref())
}
pub fn get_multi_inverse<F: Field>(a: U256) -> U256 {
    let a_hi = F::from_u128((a >> 128).as_u128());
    let a_lo = F::from_u128(a.low_u128());

    U256::from_little_endian((a_hi + a_lo).invert().unwrap_or(F::ZERO).to_repr().as_ref())
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(StorageGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::{HashMap, HashSet};
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint_sload() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut storage_contract_addr: HashMap<u64, U256> = HashMap::new();
        storage_contract_addr.insert(0x01, U256::from(0x1111));
        // 1.gas_left 赋一个初始值，可以是任意数，大一点就行
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(0x1234)),
            call_id: 0x01,
            gas_left: 0x254023,
            storage_contract_addr,
            ..WitnessExecHelper::new()
        };

        // 2.确认流程中改状态可能需要的gas消耗，例如这里的834，计算出前一个状态的值
        let gas_left_before_exec = current_state.gas_left + 0x834;
        let mut trace = prepare_trace_step!(0, OpcodeId::SLOAD, stack);
        trace
            .storage
            .0
            .insert(U256::from(0xffff), U256::from(0x1234));
        // 3. 赋值trace.gas，这一步是必须的，因为在生成witness的时候，需要trace.gas
        trace.gas = gas_left_before_exec;

        // 4. 对应padding行的下标赋值gas_left_before_exec
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
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
    #[test]
    fn assign_and_constraint_sstore() {
        let stack = Stack::from_slice(&[0x1234.into(), 0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut storage_contract_addr: HashMap<u64, U256> = HashMap::new();
        storage_contract_addr.insert(0x01, U256::from(0x1111));
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_id: 0x01,
            storage_contract_addr,
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };

        let gas_left_before_exec = current_state.gas_left + 0x5654;
        let mut trace = prepare_trace_step!(0, OpcodeId::SSTORE, stack);
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
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
