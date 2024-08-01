// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{BLOCK_IDX_LEFT_SHIFT_NUM, NUM_AUXILIARY};
use crate::execution::{
    log_topic, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{assign_or_panic, public, state, Witness, WitnessExecHelper};

use crate::util::{query_expression, ExpressionOutcome};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// LogTopicNumAddr Execution State layout is as follows
/// LOG_LEFT_X means selectors LOG_LEFT_4~LOG_LEFT_0, 5 cols, vers_8~vers_12
/// PUBLIC means public table lookup for log, 6 cols, vers_26~vers31
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+------------+----------+----------+
/// |cnt| 8 col |    8 col   |  8 col  |   8 col   |
/// +---+-------+------------+---------+-----------+
/// | 2 | not used | not used | not used | PUBLIC(6)|
/// | 1 | not used|LOG_LEFT_X(5)|not used| not used |
/// | 0 | DYNA_SELECTOR           | AUX            |
/// +---+-------+------------+--------- +---------+
///

pub(crate) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 0;
const PC_DELTA: u64 = 1;
const LOG_STAMP_DELTA: u64 = 1;
pub struct LogTopicNumAddrGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LogTopicNumAddrGadget<F>
{
    fn name(&self) -> &'static str {
        "LOG_TOPIC_NUM_ADDR"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LOG_TOPIC_NUM_ADDR
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, log_topic::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        let block_tx_idx =
            (block_idx.clone() * (1u64 << BLOCK_IDX_LEFT_SHIFT_NUM).expr()) + tx_idx.clone();

        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { log_stamp, .. } = config.get_auxiliary();
        let log_stamp = meta.query_advice(log_stamp, Rotation(NUM_ROW as i32 * -1));
        let selector = config.get_log_left_selector(meta);

        // build constraints ---
        // append auxiliary constraints
        let log_stamp_delta = selector.select(&[
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            LOG_STAMP_DELTA.expr(),
        ]);
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            log_stamp: ExpressionOutcome::Delta(log_stamp_delta),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // new selector LOG_LEFT_X and append selector constraints
        let selector = config.get_log_left_selector(meta);
        constraints.extend(selector.get_constraints());

        // get contract addr
        let (_, _, contract_addr_hi, contract_addr_lo, ..) =
            extract_lookup_expression!(state, config.get_state_lookup(meta, 0));

        // append public log lookup (addrWithXLog) constraints
        let (
            public_tag,
            public_block_tx_idx,
            public_values, // public_log_stamp, public_log_tag, public_log_addr_hi, public_log_addr_lo
        ) = extract_lookup_expression!(public, config.get_public_lookup(meta, 0));

        constraints.extend([
            (
                "public tag is tx_log".into(),
                public_tag - (public::Tag::TxLog as u8).expr(),
            ),
            (
                "public tx_idx is config.tx_idx".into(),
                public_block_tx_idx - block_tx_idx.clone(),
            ),
            (
                "public log_stamp is correct".into(),
                public_values[0].clone() - log_stamp,
            ),
            (
                "public log tag is addrWithXLog".into(),
                public_values[1].clone() - (opcode.clone() - OpcodeId::LOG0.as_u8().expr()),
            ),
            (
                "public log addr hi is contract addr hi".into(),
                public_values[2].clone() - contract_addr_hi,
            ),
            (
                "public log addr lo is contract addr lo".into(),
                public_values[3].clone() - contract_addr_lo,
            ),
        ]);

        // extend opcode and pc constraints
        constraints.extend([(
            "opcode is one of LOG0,LOG1,LOG2,LOG3,LOG4".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::LOG4.expr(),
                opcode.clone() - OpcodeId::LOG3.expr(),
                opcode.clone() - OpcodeId::LOG2.expr(),
                opcode.clone() - OpcodeId::LOG1.expr(),
                opcode - OpcodeId::LOG0.expr(),
            ]),
        )]);

        // append prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // extend pc constraints
        let pc_delta = selector.select(&[0.expr(), 0.expr(), 0.expr(), 0.expr(), PC_DELTA.expr()]);

        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(pc_delta.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // prev state should be log_gas
        // next state should be log_topic if pc_delta == 0
        let following_log_topic =
            selector.select(&[1.expr(), 1.expr(), 1.expr(), 1.expr(), 0.expr()]);
        let next_is_log_topic = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::LOG_GAS],
                NUM_ROW,
                vec![(
                    ExecutionState::LOG_TOPIC,
                    log_topic::NUM_ROW,
                    Some(next_is_log_topic),
                )],
                Some(vec![following_log_topic]),
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));

        vec![
            ("state lookup for topic".into(), stack_lookup),
            ("log topic num addr public lookup".into(), public_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let contract_addr = *current_state
            .storage_contract_addr
            .get(&current_state.call_id)
            .unwrap();
        let read_contract_addr_row = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::StorageContractAddr,
            contract_addr,
            current_state.call_id,
        );

        // core_row_1: state lookup (vers_0~vers_7) + selector LOG_LEFT_X (vers_8~vers_12) + Public Log LookUp (vers_26~vers_31)
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // core_row_1: insert lookUp: Core ---> State

        // init topic_left
        match trace.op {
            OpcodeId::LOG4 => current_state.topic_left = 4,
            OpcodeId::LOG3 => current_state.topic_left = 3,
            OpcodeId::LOG2 => current_state.topic_left = 2,
            OpcodeId::LOG1 => current_state.topic_left = 1,
            OpcodeId::LOG0 => current_state.topic_left = 0,
            _ => panic!(),
        }

        core_row_1.insert_state_lookups([&read_contract_addr_row]);
        // core_row_1: insert selector LOG_LEFT_4, LOG_LEFT_3, LOG_LEFT_2, LOG_LEFT_1, LOG_LEFT_0
        core_row_1.insert_log_left_selector(current_state.topic_left);

        // core_row_1: insert Public lookUp: Core ----> addrWithXLog  to core_row_1.vers_26 ~ vers_31
        let public_row = current_state.get_public_log_topic_num_addr_row(trace.op);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_public_lookup(0, &public_row);

        // increase log_stamp when topic_left == 0
        if current_state.topic_left == 0 {
            current_state.log_stamp += 1;
        }

        let mut core_row_0 = ExecutionState::LOG_TOPIC_NUM_ADDR.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // 如果下一个状态为log_topic,设置NUM_STATE_HI_COL+NUM_STATE_LO_COL+NUM_AUXILIARY 为1
        match current_state.next_exec_state {
            Some(ExecutionState::LOG_TOPIC) => {
                assign_or_panic!(
                    core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
                    U256::one()
                );
            }
            _ => (),
        }
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![read_contract_addr_row],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(LogTopicNumAddrGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::LOG_STAMP_IDX;
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use crate::witness::WitnessExecHelper;
    generate_execution_gadget_test_circuit!();

    fn assign_and_constraint(next_state: ExecutionState, opcode: OpcodeId, stack: Stack) {
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
            gas_left: 100,
            ..WitnessExecHelper::new()
        };
        current_state
            .storage_contract_addr
            .insert(call_id, current_state.code_addr);

        let trace = prepare_trace_step!(0, opcode, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::LOG_GAS.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + LOG_STAMP_IDX] = Some(log_stamp.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = next_state.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            if next_state.clone() == ExecutionState::END_PADDING {
                row.pc = 1.into();
                row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + LOG_STAMP_IDX] =
                    Some((log_stamp + 1).into());
            }

            row
        };
        current_state.next_exec_state = Some(next_state);
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied();
    }

    #[test]
    fn test_log_topic_num_addr_log0() {
        // test next state is not log topic
        let opcode = OpcodeId::LOG0;
        let stack = Stack::from_slice(&[0x4.into(), 0x1.into()]);
        assign_and_constraint(ExecutionState::END_PADDING, opcode, stack)
    }

    #[test]
    fn test_log_topic_num_add_log1() {
        // test next state is log topic
        let opcode = OpcodeId::LOG1;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(ExecutionState::LOG_TOPIC, opcode, stack)
    }

    #[test]
    fn test_log_topic_num_add_log2() {
        // test next state is log topic
        let opcode = OpcodeId::LOG2;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(ExecutionState::LOG_TOPIC, opcode, stack)
    }

    #[test]
    fn test_log_topic_num_add_log3() {
        // test next state is log topic
        let opcode = OpcodeId::LOG3;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b95".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(ExecutionState::LOG_TOPIC, opcode, stack)
    }

    #[test]
    fn test_log_topic_num_add_log4() {
        // test next state is log topic
        let opcode = OpcodeId::LOG4;
        let stack = Stack::from_slice(&[
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b95".into(),
            "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b96".into(),
            0x4.into(),
            0x1.into(),
        ]);
        assign_and_constraint(ExecutionState::LOG_TOPIC, opcode, stack)
    }
}
