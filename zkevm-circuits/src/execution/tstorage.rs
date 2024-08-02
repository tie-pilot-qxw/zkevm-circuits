// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::core_circuit::{concat_block_tx_idx, concat_block_tx_idx_expr};
use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::Witness;
use crate::witness::{state, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const PC_DELTA: u64 = 1;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA_TLOAD: i32 = 0;
const STACK_POINTER_DELTA_TSTORE: i32 = -2;

pub struct TStorageGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for TStorageGadget<F>
{
    fn name(&self) -> &'static str {
        "TSTORAGE"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::TSTORAGE
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
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_tx_idx = concat_block_tx_idx_expr(block_idx, tx_idx);
        let Auxiliary {
            state_stamp,
            stack_pointer,
            ..
        } = config.get_auxiliary();
        let stamp = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let stack_pointer = meta.query_advice(stack_pointer, Rotation(-1 * NUM_ROW as i32));

        let is_tload = OpcodeId::TSTORE.as_u8().expr() - opcode.clone();
        let is_tstore = opcode.clone() - OpcodeId::TLOAD.as_u8().expr();

        // auxiliary constrains
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(
                STACK_POINTER_DELTA_TLOAD.expr() * is_tload.clone()
                    + STACK_POINTER_DELTA_TSTORE.expr() * is_tstore.clone(),
            ),
            gas_left: ExpressionOutcome::Delta(
                -OpcodeId::TLOAD.constant_gas_cost().expr() * is_tload.clone()
                    - OpcodeId::TSTORE.constant_gas_cost().expr() * is_tstore.clone(),
            ),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // pop key from stack
        let read_stack_key = config.get_state_lookup(meta, 0);
        constraints.extend(config.get_stack_constraints(
            meta,
            read_stack_key.clone(),
            0,
            NUM_ROW,
            0.expr(),
            false,
        ));
        let (_, _, key_hi, key_lo, ..) = extract_lookup_expression!(state, read_stack_key);

        // is_tload: read storage value
        // is_tstore: get storage value from cur_step stack (pop stack, stack_pointer-1)
        let state_lookup_1 = config.get_state_lookup(meta, 1);
        constraints.extend(config.get_state_constraints(
            state_lookup_1.clone(),
            1,
            is_tload.clone() * (state::Tag::TStorage as u8).expr()
                + is_tstore.clone() * (state::Tag::Stack as u8).expr(),
            is_tload.clone() * block_tx_idx.clone() + is_tstore.clone() * call_id.clone(),
            is_tload.clone() * key_hi.clone() + is_tstore.clone() * 0.expr(),
            is_tload.clone() * key_lo.clone()
                + is_tstore.clone() * (stack_pointer.clone() - 1.expr()),
            stamp.clone() + 1.expr(),
            0.expr(),
        ));
        let (_, _, read_value_hi, read_value_lo, ..) =
            extract_lookup_expression!(state, state_lookup_1);

        // is_load: push value to stack top
        // is_store: write value to storage
        let state_lookup_2 = config.get_state_lookup(meta, 2);
        constraints.extend(config.get_state_constraints(
            state_lookup_2.clone(),
            2,
            is_tload.clone() * (state::Tag::Stack as u8).expr()
                + is_tstore.clone() * (state::Tag::TStorage as u8).expr(),
            is_tload.clone() * call_id.clone() + is_tstore.clone() * block_tx_idx.clone(),
            is_tload.clone() * 0.expr() + is_tstore.clone() * (key_hi.clone()),
            is_tload.clone() * stack_pointer.clone() + is_tstore.clone() * (key_lo.clone()),
            stamp.clone() + 2.expr(),
            1.expr(),
        ));
        let (_, _, write_value_hi, write_value_lo, ..) =
            extract_lookup_expression!(state, state_lookup_2);

        // value constraints
        constraints.extend(vec![
            (
                "read_value_hi == write_value_hi".into(),
                read_value_hi - write_value_hi,
            ),
            (
                "read_value_lo == write_value_lo".into(),
                read_value_lo - write_value_lo,
            ),
        ]);

        // opcode constraints
        constraints.push((
            "opcode".into(),
            (opcode.clone() - OpcodeId::TLOAD.expr()) * (opcode - OpcodeId::TSTORE.expr()),
        ));
        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let state_read_key_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let state_read_value_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let state_write_value_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            ("state read key lookup".into(), state_read_key_lookup),
            ("state read value lookup".into(), state_read_value_lookup),
            ("state write value lookup".into(), state_write_value_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::TLOAD || trace.op == OpcodeId::TSTORE);

        let block_tx_idx =
            concat_block_tx_idx(current_state.block_idx.into(), current_state.tx_idx.into());

        //generate storage pop key row
        let (state_read_key_row, storage_key) = current_state.get_pop_stack_row_value(&trace);

        // Because TSTORE and TLOAD are definitely transactions for the same key in the same transaction,
        // the data of TLOAD can definitely be looked up in the state.
        let (state_read_value_row, state_write_value_row) = match trace.op {
            OpcodeId::TLOAD => {
                // get transient value, if TLOAD a non-existent key, the value obtained should be 0
                let storage_value = *current_state
                    .transient_storage
                    .get(&storage_key)
                    .unwrap_or(&U256::zero());
                assert_eq!(current_state.stack_top.unwrap(), storage_value);
                let storage_read_row =
                    current_state.get_tstorage_row(storage_key, storage_value, block_tx_idx, false);
                let stack_push_row = current_state.get_push_stack_row(&trace, storage_value);

                (storage_read_row, stack_push_row)
            }
            OpcodeId::TSTORE => {
                let (stack_pop_row, value) = current_state.get_pop_stack_row_value(&trace);
                let storage_write_row =
                    current_state.get_tstorage_row(storage_key, value, block_tx_idx, true);
                // save transient value
                current_state.transient_storage.insert(storage_key, value);
                (stack_pop_row, storage_write_row)
            }
            _ => unreachable!(),
        };
        //generate core row
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookup
        core_row_1.insert_state_lookups([
            &state_read_key_row,
            &state_read_value_row,
            &state_write_value_row,
        ]);

        let core_row_0 = ExecutionState::TSTORAGE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                state_read_key_row,
                state_read_value_row,
                state_write_value_row,
            ],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(TStorageGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::HashMap;

    generate_execution_gadget_test_circuit!();

    fn run(opcode: OpcodeId, mut current_state: WitnessExecHelper, stack: Stack) {
        //  确认流程中改状态可能需要的gas消耗，例如这里的834，计算出前一个状态的值
        // TLOAD和TSTORE的gas是常量(100)
        let gas_left_before_exec = current_state.gas_left + 0x64;
        let mut trace = prepare_trace_step!(0, opcode, stack);
        // 3. 赋值trace.gas，这一步是必须的，因为在生成witness的时候，需要trace.gas
        trace.gas = gas_left_before_exec;

        // 对应padding行的下标赋值gas_left_before_exec
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(current_state.stack_pointer.into());
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
    fn test_tload() {
        let key = 0xa;
        let call_id = 0x01;
        let value = U256::from(0x1234);

        let stack = Stack::from_slice(&[key.into()]);

        let mut transient_storage: HashMap<U256, U256> = HashMap::new();
        transient_storage.insert(key.into(), value.into());

        // gas_left 赋一个初始值，可以是任意数，大一点就行
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(value),
            call_id,
            gas_left: 0x254023,
            transient_storage,
            block_idx: 10,
            tx_idx: 20,
            ..WitnessExecHelper::new()
        };

        run(OpcodeId::TLOAD, current_state, stack);
    }

    #[test]
    fn test_tstore() {
        let key = 0xa;
        let value = 0x1234;
        let call_id = 0x01;

        // value key: 0xa
        let stack = Stack::from_slice(&[value.into(), key.into()]);

        // gas_left 赋一个初始值，可以是任意数，大一点就行
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(0x1234)),
            call_id,
            gas_left: 0x254023,
            block_idx: 10,
            tx_idx: 20,
            ..WitnessExecHelper::new()
        };

        run(OpcodeId::TSTORE, current_state, stack);
    }
}
