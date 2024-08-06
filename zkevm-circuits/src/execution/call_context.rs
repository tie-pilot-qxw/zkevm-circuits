// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::state::CallContextTag;
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = 1;
const CORE_ROW_1_START_COL_IDX: usize = 28;

/// CallContextGadget deal OpCodeId:{CALLDATASIZE, CALLER, CALLVALUE, ADDRESS}
/// STATE0 read value from call_context
/// STATE1 write value to stack
/// TAGSELECTOR 4 columns
/// +---+-------+-------+------------------+
/// |cnt| 8 col | 8 col |     16 col       |
/// +---+-------+-------+------------------+
/// | 1 | STATE1| STATE2|       TAGSELECTOR|
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+------------------+
pub struct CallContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CallContextGadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_CONTEXT
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // CALLER, CALLVALUE, CALLDATASIZE and ADDRESS gas cost is QUICK,
            // Only one of the representatives is used here
            gas_left: ExpressionOutcome::Delta(-OpcodeId::CALLER.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let calldatasize_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev());
        let caller_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev());
        let callvalue_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev());
        let address_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 3], Rotation::prev());
        // create a simple selector representing:
        // - CALLDATASIZE,
        // - CALLER,
        // - CALLVALUE,
        // - ADDRESS.
        let selector =
            SimpleSelector::new(&[calldatasize_tag, caller_tag, callvalue_tag, address_tag]);
        constraints.extend(selector.get_constraints());

        // opcode constraints
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.extend([(
            "opcode is correct".into(),
            opcode
                - selector.select(&[
                    OpcodeId::CALLDATASIZE.as_u8().expr(),
                    OpcodeId::CALLER.as_u8().expr(),
                    OpcodeId::CALLVALUE.as_u8().expr(),
                    OpcodeId::ADDRESS.as_u8().expr(),
                ]),
        )]);

        // select call context tag
        let call_context_tag = selector.select(&[
            (CallContextTag::CallDataSize as u8).expr(),
            (CallContextTag::SenderAddr as u8).expr(),
            (CallContextTag::Value as u8).expr(),
            (CallContextTag::StorageContractAddr as u8).expr(),
        ]);

        // get operands from lookups and constraints them
        let mut operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);

            if i == 0 {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    call_context_tag.clone(),
                    call_id.clone(),
                ));
            } else {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    STACK_POINTER_DELTA.expr(),
                    true,
                ));
            }

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // constraints call context value = stack push value
        let call_context_value = &operands[0];
        let stack_push_value = &operands[1];
        constraints.extend([
            (
                "call context value hi = stack push value hi".into(),
                call_context_value[0].clone() - stack_push_value[0].clone(),
            ),
            (
                "call context value lo = stack push value lo".into(),
                call_context_value[1].clone() - stack_push_value[1].clone(),
            ),
        ]);

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let state_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let state_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        vec![
            ("call context read lookup".into(), state_lookup_0),
            ("stack push lookup".into(), state_lookup_1),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (call_context, value) = current_state.get_call_context_read_row(trace.op);
        assert_eq!(value, current_state.stack_top.unwrap());

        let stack_push = current_state.get_push_stack_row(trace, value);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        let tag = match trace.op {
            OpcodeId::CALLDATASIZE => 0,
            OpcodeId::CALLER => 1,
            OpcodeId::CALLVALUE => 2,
            OpcodeId::ADDRESS => 3,
            _ => panic!("not CALLDATASIZE, CALLER, CALLVALUE or ADDRESS"),
        };

        core_row_1.insert_state_lookups([&call_context, &stack_push]);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
                CORE_ROW_1_START_COL_IDX + 3,
            ],
            tag,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::CALL_CONTEXT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![call_context, stack_push],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CallContextGadget {
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

    #[test]
    fn test_address() {
        let stack = Stack::from_slice(&[]);
        let mut storage_contract_addr = HashMap::new();
        storage_contract_addr.insert(0, 0x123.into());
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0x123.into()),
            gas_left: 0x254023,
            storage_contract_addr,
            ..WitnessExecHelper::new()
        };
        run(current_state, stack, OpcodeId::ADDRESS);
    }

    #[test]
    fn test_calldata_size() {
        let stack = Stack::from_slice(&[]);
        let mut call_data = HashMap::new();
        call_data.insert(0_u64, vec![1_u8, 2_u8]);
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0x2.into()),
            gas_left: 0x254023,
            call_data,
            ..WitnessExecHelper::new()
        };
        run(current_state, stack, OpcodeId::CALLDATASIZE);
    }

    #[test]
    fn test_caller() {
        let stack = Stack::from_slice(&[]);
        let mut sender = HashMap::new();
        sender.insert(0_u64, U256::max_value());
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::max_value()),
            gas_left: 0x254023,
            sender,
            ..WitnessExecHelper::new()
        };
        run(current_state, stack, OpcodeId::CALLER);
    }

    #[test]
    fn test_call_value() {
        let stack = Stack::from_slice(&[]);
        let mut value = HashMap::new();
        value.insert(0, 0xff.into());
        let current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            gas_left: 0x254023,
            value,
            ..WitnessExecHelper::new()
        };
        run(current_state, stack, OpcodeId::CALLVALUE);
    }

    fn run(mut current_state: WitnessExecHelper, stack: Stack, op: OpcodeId) {
        let stack_pointer = stack.0.len();
        let gas_left_before_exec = current_state.gas_left + op.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, op, stack);
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
