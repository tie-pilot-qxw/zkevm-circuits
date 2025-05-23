// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

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

use crate::execution::{AuxiliaryOutcome, CoreSinglePurposeOutcome};

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
const CORE_ROW_1_START_COL_IDX: usize = 8;
const PC_DELTA: u64 = 1;

/// PublicContextGadget deal OpCodeId:{TIMESTAMP,NUMBER,COINBASE,GASLIMIT,CHAINID,BASEFEE}
/// STATE0 record value
/// TAGSEL 7 columns
/// PUB_VAL 2 columns, others public values for public constraints
/// TAG 1 column, means public tag (column 26)
/// if opcode is OpCodeId::TIMESTAMP ,tag is public::Tag::BlockCoinbaseAndTimestamp
/// if opcode is OpCodeId::NUMBER , tag is public::Tag::BlockNumber
/// if opcode is OpCodeId::COINBASE , tag is public::Tag::BlockCoinbaseAndTimestamp
/// if opcode is OpCodeId::GASLIMIT , tag is public::Tag::BlockGasLimitAndBaseFee
/// if opcode is OpCodeId::CHAINID , tag is public::Tag::ChainId
/// if opcode is OpCodeId::BASEFEE , tag is public::Tag::BlockGasLimitAndBaseFee
/// if opcode is OpCodeId::PREVRANDAO(same as DIFFICULTY, 0x44), tag is public::Tag::BlockTxLogNumAndPrevrandao
/// IDX 1 column,default 0, means public table tx_idx (column 27)
/// VALUE_0 1 column , means public table value0 (column 28)
/// VALUE_1 1 column, means public table value1 (column 29)
/// VALUE_2 1 column , means public table value2 (column 30)
/// VALUE_3 1 column ,means public table value3 (column 31)
/// +---+-------+-------+-------+-------+----------------------------------------------------------+
/// |cnt| 8 col | 8 col | 8 col | 2 col |              public lookup (6 col)                       |
/// +---+-------+-------+-------+------------------------------------------------------------------+
/// | 2 |       |       |       |               |TAG | IDX | VALUE_0 | VALUE_1 | VALUE_2 | VALUE_3 |
/// | 1 | STATE0|TAGSEL| PUB_VAL|                                                                  |
/// | 0 | DYNA_SELECTOR   |                                 AUX                                    |
/// +---+-------+-------+-------+------------------------------------------------------------------+
pub struct PublicContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PublicContextGadget<F>
{
    fn name(&self) -> &'static str {
        "PUBLIC_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::PUBLIC_CONTEXT
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
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());

        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // COINBASE, TIMESTAMP, NUMBER, GASLIMIT, CHAINID, BASEFEE, PREVRANDAO gas cost == QUICK,
            // Only one of the representatives is used here
            gas_left: ExpressionOutcome::Delta(-OpcodeId::TIMESTAMP.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
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
            STACK_POINTER_DELTA.expr(),
            true,
        ));
        // value_hi,value_lo constraints
        let (_, _, state_value_hi, state_value_lo, _, _, _, _) =
            extract_lookup_expression!(state, entry);
        // public lookup
        let public_entry = config.get_public_lookup(meta, 0);
        // query public_tag , only one tag is 1,other tag is 0;
        let timestamp_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev());
        let number_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev());
        let coinbase_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev());
        let gaslimit_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 3], Rotation::prev());
        let chainid_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 4], Rotation::prev());
        let basefee_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 5], Rotation::prev());
        let prevrandao_tag =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 6], Rotation::prev());
        let public_value_hi =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 7], Rotation::prev());
        let public_value_lo =
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 8], Rotation::prev());

        // Create a simple selector with input of array of expressions,which is 0.expr() or 1.expr();
        let selector = SimpleSelector::new(&[
            timestamp_tag.clone(),
            number_tag.clone(),
            coinbase_tag.clone(),
            gaslimit_tag.clone(),
            chainid_tag.clone(),
            basefee_tag.clone(),
            prevrandao_tag.clone(),
        ]);
        constraints.extend(selector.get_constraints());

        let public_tag = selector.select(&[
            (Tag::BlockCoinbaseAndTimestamp as u64).expr(),
            (Tag::BlockNumber as u64).expr(),
            (Tag::BlockCoinbaseAndTimestamp as u64).expr(),
            (Tag::BlockGasLimitAndBaseFee as u64).expr(),
            (Tag::ChainId as u64).expr(),
            (Tag::BlockGasLimitAndBaseFee as u64).expr(),
            (Tag::BlockTxLogNumAndPrevrandao as u64).expr(),
        ]);

        let idx = Some(selector.select(&[
            block_idx.clone(),
            0.expr(),
            block_idx.clone(),
            block_idx.clone(),
            0.expr(),
            block_idx.clone(),
            block_idx.clone(),
        ]));

        let value_0 = Some(selector.select(&[
            public_value_hi.clone(),
            state_value_hi.clone(),
            state_value_hi.clone(),
            state_value_hi.clone(),
            state_value_hi.clone(),
            public_value_hi.clone(),
            public_value_hi.clone(),
        ]));

        let value_1 = Some(selector.select(&[
            public_value_lo.clone(),
            // When Opcode == BlockNumber, should calculate Block Number First Block  = state_value_lo - (block_idx - 1)
            state_value_lo.clone() - number_tag.clone() * (block_idx.clone() - 1.expr()),
            state_value_lo.clone(),
            state_value_lo.clone(),
            state_value_lo.clone(),
            public_value_lo.clone(),
            public_value_lo.clone(),
        ]));

        let value_2 = Some(selector.select(&[
            state_value_hi.clone(),
            public_value_hi.clone(),
            public_value_hi.clone(),
            public_value_hi.clone(),
            public_value_hi.clone(),
            state_value_hi.clone(),
            state_value_hi.clone(),
        ]));

        let value_3 = Some(selector.select(&[
            state_value_lo.clone(),
            public_value_lo.clone(),
            public_value_lo.clone(),
            public_value_lo.clone(),
            public_value_lo.clone(),
            state_value_lo.clone(),
            state_value_lo.clone(),
        ]));

        // public constraints
        constraints.extend(config.get_public_constraints(
            meta,
            public_entry,
            public_tag,
            idx,
            [value_0, value_1, value_2, value_3],
        ));

        // opcode constraints
        constraints.push((
            "opcode constraints".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::TIMESTAMP.as_u64().expr(),
                opcode.clone() - OpcodeId::NUMBER.as_u64().expr(),
                opcode.clone() - OpcodeId::COINBASE.as_u64().expr(),
                opcode.clone() - OpcodeId::GASLIMIT.as_u64().expr(),
                opcode.clone() - OpcodeId::CHAINID.as_u64().expr(),
                opcode.clone() - OpcodeId::BASEFEE.as_u64().expr(),
                opcode.clone() - OpcodeId::DIFFICULTY.as_u64().expr(),
            ]),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // state lookup
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        // public lookup
        let public_context_lookup =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stack push value lookup".into(), stack_lookup_0),
            ("public context value lookup".into(), public_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let next_stack_top_value = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, next_stack_top_value);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // get value for public lookup
        let public_row = match trace.op {
            OpcodeId::COINBASE | OpcodeId::TIMESTAMP => {
                current_state.get_public_tx_row(Tag::BlockCoinbaseAndTimestamp, 0)
            }
            OpcodeId::GASLIMIT | OpcodeId::BASEFEE => {
                current_state.get_public_tx_row(Tag::BlockGasLimitAndBaseFee, 0)
            }
            OpcodeId::NUMBER => current_state.get_public_tx_row(Tag::BlockNumber, 0),
            OpcodeId::CHAINID => current_state.get_public_tx_row(Tag::ChainId, 0),
            OpcodeId::DIFFICULTY => {
                current_state.get_public_tx_row(Tag::BlockTxLogNumAndPrevrandao, 0)
            }
            _ => panic!("not PUBLIC_CONTEXT op"),
        };

        // get PUB_VAL
        let (pub_value_hi, pub_value_lo) = match trace.op {
            OpcodeId::TIMESTAMP | OpcodeId::BASEFEE | OpcodeId::DIFFICULTY => (
                public_row.value_0.unwrap_or_default(), // if value is None, assign 0
                public_row.value_1.unwrap_or_default(),
            ),
            _ => (
                public_row.value_2.unwrap_or_default(),
                public_row.value_3.unwrap_or_default(),
            ),
        };

        // core_row_2
        core_row_2.insert_public_lookup(0, &public_row);

        // core_row_1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push_0]);

        // tag selector
        // assign tag selector value, 8-14 columns ,only one column is 1 ,others are 0;
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX + 0,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
                CORE_ROW_1_START_COL_IDX + 3,
                CORE_ROW_1_START_COL_IDX + 4,
                CORE_ROW_1_START_COL_IDX + 5,
                CORE_ROW_1_START_COL_IDX + 6,
            ],
            match trace.op {
                OpcodeId::TIMESTAMP => 0,
                OpcodeId::NUMBER => 1,
                OpcodeId::COINBASE => 2,
                OpcodeId::GASLIMIT => 3,
                OpcodeId::CHAINID => 4,
                OpcodeId::BASEFEE => 5,
                OpcodeId::DIFFICULTY => 6,
                _ => panic!("not PUBLIC_CONTEXT op"),
            },
            |cell, value| assign_or_panic!(*cell, value.into()),
        );
        assign_or_panic!(
            core_row_1[CORE_ROW_1_START_COL_IDX + 7],
            pub_value_hi.into()
        );
        assign_or_panic!(
            core_row_1[CORE_ROW_1_START_COL_IDX + 8],
            pub_value_lo.into()
        );

        // core row 2
        let core_row_0 = ExecutionState::PUBLIC_CONTEXT.into_exec_state_core_row(
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
    Box::new(PublicContextGadget {
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

    fn run(op_code: OpcodeId) {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            gas_left: 0x254023,
            timestamp: 0xff.into(),
            coinbase: 0xff.into(),
            block_gaslimit: 0xff.into(),
            basefee: 0xff.into(),
            prevrandao: 0xff.into(),
            chain_id: 0xff.into(),
            tx_gaslimit: 0xff.into(),
            block_num_in_chunk: 20,
            block_number_first_block: 0xf1,
            block_idx: 0xf,
            ..WitnessExecHelper::new()
        };
        current_state.tx_num_in_block.insert(0xf, 0xf);
        current_state.log_num_in_block.insert(0xf, 0xf);

        let gas_left_before_exec = current_state.gas_left + OpcodeId::TIMESTAMP.constant_gas_cost();
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
    #[test]
    fn assign_opcode_run() {
        run(OpcodeId::CHAINID);
        run(OpcodeId::TIMESTAMP);
        run(OpcodeId::NUMBER);
        run(OpcodeId::COINBASE);
        run(OpcodeId::GASLIMIT);
        run(OpcodeId::BASEFEE);
        run(OpcodeId::DIFFICULTY);
    }
}
