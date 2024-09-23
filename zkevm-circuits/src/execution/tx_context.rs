// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::core_circuit::concat_block_tx_idx_expr;
use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::Tag;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::{AuxiliaryOutcome, CoreSinglePurposeOutcome};

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
const ORIGIN_TAG_COL_IDX: usize = 8;
const GAS_PRICE_TAG_COL_IDX: usize = 9;
const PUB_VALUE_COL_IDX: usize = 10;

/// TxContextGadget deal OpCodeId:{ORIGIN,GASPRICE}
/// STATE0 record value
/// TAGSELECTOR 2 columns
/// PUB_VAL 2 columns
/// PUBLIC 6 columns, including:
/// - TAG 1 column, means public tag (column 26)
/// - TX_IDX_0 1 column,default 0, means public table tx_idx (column 27)
/// - VALUE_HI 1 column , means public table value0 (column 28)
/// - VALUE_LOW 1 column, means public table value1 (column 29)
/// - VALUE_2 1 column , means public table value2 , here from_high (column 30)
/// - VALUE_3 1 column ,means public table value3 , here from_low (column 31)
/// +---+-------+-------+-------+-------+-------+
/// |cnt| 8 col | 8 col | 8 col | 2 col | 6 col |
/// +---+-------+-------+-------+---------------+
/// | 2 |                               |PUBLIC |
/// | 1 | STATE0| TAGSELECTOR | PUB_VAL |       |
/// | 0 | DYNA_SELECTOR        | AUX            |
/// +---+-------+-------+-------+-------+-------+
pub struct TxContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for TxContextGadget<F>
{
    fn name(&self) -> &'static str {
        "TX_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::TX_CONTEXT
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        let block_tx_idx = concat_block_tx_idx_expr(block_idx.clone(), tx_idx.clone());

        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // ORIGIN, GASPRICE gas cost == QUICK
            gas_left: ExpressionOutcome::Delta(-OpcodeId::ORIGIN.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // stack constraints
        let entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            entry.clone(),
            0,
            NUM_ROW,
            1i32.expr(),
            true,
        ));
        // value_hi,value_lo constraints
        let (_, _, state_value_hi, state_value_lo, _, _, _, _) =
            extract_lookup_expression!(state, entry);
        let public_entry = config.get_public_lookup(meta, 0);
        let origin_tag = meta.query_advice(config.vers[ORIGIN_TAG_COL_IDX], Rotation::prev());
        let gasprice_tag = meta.query_advice(config.vers[GAS_PRICE_TAG_COL_IDX], Rotation::prev());
        let pub_value_hi = meta.query_advice(config.vers[PUB_VALUE_COL_IDX], Rotation::prev());
        let pub_value_lo = meta.query_advice(config.vers[PUB_VALUE_COL_IDX + 1], Rotation::prev());

        let selector = SimpleSelector::new(&[origin_tag.clone(), gasprice_tag.clone()]);
        constraints.extend(selector.get_constraints());

        // pubic lookup constraints
        constraints.extend(config.get_public_constraints(
            meta,
            public_entry,
            selector.select(&[
                (Tag::TxFromValue as u64).expr(),
                (Tag::TxGasLimitAndGasPrice as u64).expr(),
            ]),
            Some(block_tx_idx.clone()),
            [
                Some(selector.select(&[state_value_hi.clone(), pub_value_hi.clone()])),
                Some(selector.select(&[state_value_lo.clone(), pub_value_lo.clone()])),
                Some(selector.select(&[pub_value_hi.clone(), state_value_hi.clone()])),
                Some(selector.select(&[pub_value_lo.clone(), state_value_lo.clone()])),
            ],
        ));
        // opcode constraints
        constraints.extend([(
            "opcode constraints".into(),
            opcode
                - selector.select(&[
                    OpcodeId::ORIGIN.as_u8().expr(),
                    OpcodeId::GASPRICE.as_u8().expr(),
                ]),
        )]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));

        let public_context_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stack push value lookup".into(), stack_lookup_0),
            ("tx context value lookup".into(), public_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let next_stack_top_value = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, next_stack_top_value);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        let (public_row, pub_value_hi, pub_value_lo) = match trace.op {
            OpcodeId::ORIGIN => {
                let row = current_state.get_public_tx_row(public::Tag::TxFromValue, 0);
                (
                    row.clone(),
                    row.clone().value_2.unwrap_or(U256::zero()),
                    row.clone().value_3.unwrap_or(U256::zero()),
                )
            }
            OpcodeId::GASPRICE => {
                let row = current_state.get_public_tx_row(public::Tag::TxGasLimitAndGasPrice, 0);
                (
                    row.clone(),
                    row.clone().value_0.unwrap_or(U256::zero()),
                    row.clone().value_1.unwrap_or(U256::zero()),
                )
            }
            _ => panic!("not ORIGIN or GASPRICE"),
        };

        // core_row_2
        core_row_2.insert_public_lookup(0, &public_row);

        // core_row_1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push_0]);

        simple_selector_assign(
            &mut core_row_1,
            [ORIGIN_TAG_COL_IDX, GAS_PRICE_TAG_COL_IDX],
            if trace.op == OpcodeId::ORIGIN { 0 } else { 1 },
            |cell, value| assign_or_panic!(*cell, value.into()),
        );
        assign_or_panic!(core_row_1[PUB_VALUE_COL_IDX], pub_value_hi.into());
        assign_or_panic!(core_row_1[PUB_VALUE_COL_IDX + 1], pub_value_lo.into());

        // core_row 0
        let core_row_0 = ExecutionState::TX_CONTEXT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(TxContextGadget {
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
    fn assign_opcode_run() {
        run(OpcodeId::ORIGIN);
        run(OpcodeId::GASPRICE);
    }

    fn run(op_code: OpcodeId) {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut sender = HashMap::new();
        sender.insert(0_u64, U256::max_value() - 1);
        let mut value = HashMap::new();
        value.insert(0_u64, U256::max_value() - 1);

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            sender,
            gas_left: 0x254023,
            tx_gaslimit: 0x254023.into(),
            tx_value: U256::max_value() - 2,
            value,
            ..WitnessExecHelper::new()
        };
        if op_code == OpcodeId::GASPRICE {
            current_state.stack_top = Some(0.into());
        } else {
            current_state.stack_top = Some(U256::max_value() - 1);
        }

        let gas_left_before_exec = current_state.gas_left + OpcodeId::ORIGIN.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, op_code, stack);
        trace.gas = gas_left_before_exec;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
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
