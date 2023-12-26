use crate::execution::{
    Auxiliary, AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{assign_or_panic, copy, public, Witness, WitnessExecHelper};

use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::LogTag;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// LogTopic Execution State layout is as follows
/// STATE means state table lookup for topic, 8 cols, vers_0~vers_7
/// LOG_LEFT_X means selectors LOG_LEFT_4~LOG_LEFT_0, 5 cols, vers_8~vers_12
/// PUBLIC means public table lookup for log, 6 cols, vers_26~vers31
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+------------+----------+----------+
/// |cnt| 8 col |    8 col   |  8 col  |   8 col   |
/// +---+-------+------------+----------+----------+
/// | 2 | 26 col(not used)             | PUBLIC(6) |
/// | 1 | STATE | LOG_LEFT_X(5) | 19 col(not used) |
/// | 0 | DYNA_SELECTOR           | AUX            |
/// +---+-------+------------+--------- +---------+
///

const NUM_ROW: usize = 3;

const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = -1;

const PC_DELTA: u64 = 1;
const LOG_STAMP_DELTA: u64 = 1;

pub struct LogTopicGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LogTopicGadget<F>
{
    fn name(&self) -> &'static str {
        "LOG_TOPIC"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LOG_TOPIC
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
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            log_stamp: log_stamp_delta,
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // new selector LOG_LEFT_X and append selector constraints
        constraints.extend(selector.get_constraints());

        let state_entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            state_entry.clone(),
            0,
            NUM_ROW,
            0.expr(),
            false,
        ));

        let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, state_entry);

        // append public log lookup (addrWithXLog) constraints
        let (
            public_tag,
            public_tx_idx,
            public_values, // public_log_stamp, public_log_tag, public_log_addr_hi, public_log_addr_lo
        ) = extract_lookup_expression!(public, config.get_public_lookup(meta));

        constraints.extend([
            (
                format!("public tag is tx_log").into(),
                public_tag - (public::Tag::TxLog as u8).expr(),
            ),
            (
                format!("public tx_idx is config.tx_idx").into(),
                public_tx_idx - tx_idx.clone(),
            ),
            (
                format!("public log stamp is correct").into(),
                public_values[0].clone() - log_stamp,
            ),
            (
                format!("public topic log tag is TopicX depends on LOG_LEFT_X and opcode").into(),
                selector.select(&[
                    public_values[1].clone() - (LogTag::Topic0 as u8).expr(), // LOG_LEFT_4
                    (opcode.expr() - (OpcodeId::LOG0).as_u8().expr())
                        - (public_values[1].clone() - (LogTag::Topic0 as u8).expr())
                        - 3.expr(), // LOG_LEFT_3
                    (opcode.expr() - (OpcodeId::LOG0).as_u8().expr())
                        - (public_values[1].clone() - (LogTag::Topic0 as u8).expr())
                        - 2.expr(), // LOG_LEFT_2
                    (opcode.expr() - (OpcodeId::LOG0).as_u8().expr())
                        - (public_values[1].clone() - (LogTag::Topic0 as u8).expr())
                        - 1.expr(), // LOG_LEFT_1
                    (opcode.expr() - (OpcodeId::LOG0).as_u8().expr())
                        - (public_values[1].clone() - (LogTag::Topic0 as u8).expr()), // LOG_LEFT_0
                ]),
            ),
            (
                format!("public topic hash hi is stack value_hi").into(),
                public_values[2].clone() - value_hi.clone(),
            ),
            (
                format!("public topic hash lo is stack value_lo").into(),
                public_values[3].clone() - value_lo.clone(),
            ),
        ]);

        // extend pc constraints
        let pc_delta = selector.select(&[0.expr(), 0.expr(), 0.expr(), 0.expr(), PC_DELTA.expr()]);
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(pc_delta.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta));

        vec![
            ("state lookup for topic".into(), stack_lookup),
            ("public lookup".into(), public_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // decrease topic_left
        if current_state.topic_left > 0 {
            current_state.topic_left -= 1;
        }
        // get topic from stack top
        let (stack_pop_topic, _) = current_state.get_pop_stack_row_value(&trace);

        // core_row_1: state lookup (vers_0~vers_7) + selector LOG_LEFT_X (vers_8~vers_12) + Public Log LookUp (vers_26~vers_31)
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // core_row_1: insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&stack_pop_topic]);

        // core_row_1: insert selector LOG_LEFT_4, LOG_LEFT_3, LOG_LEFT_2, LOG_LEFT_1, LOG_LEFT_0
        core_row_1.insert_log_left_selector(current_state.topic_left);

        // core_row_1: insert Public lookUp: Core ----> addrWithXLog  to core_row_1.vers_26 ~ vers_31
        let public_row = current_state.get_public_log_topic_row(
            trace.op,
            stack_pop_topic.value_hi,
            stack_pop_topic.value_lo,
        );
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_public_lookup(&public_row);

        // increase log_stamp when topic_left == 0
        if current_state.topic_left == 0 {
            current_state.log_stamp += 1;
        }
        let core_row_0 = ExecutionState::LOG_TOPIC.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let mut state_rows = vec![stack_pop_topic];

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(LogTopicGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use crate::witness::WitnessExecHelper;
    use std::hash::Hash;
    generate_execution_gadget_test_circuit!();
    #[test]
    fn test_log_topic_log1() {
        let opcode = OpcodeId::LOG1;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x1;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
        let topic_left = 1;

        let stack = Stack::from_slice(&[topic0_hash.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            code_addr,
            log_stamp,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, opcode, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row.vers_22 = Some(log_stamp.into());
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
            row.vers_22 = Some((log_stamp + 1).into());
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
    #[test]
    fn test_log_topic_log2() {
        let opcode = OpcodeId::LOG2;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94";
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x1;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
        let topic_left = 2;

        let stack = Stack::from_slice(&[topic1_hash.into(), topic0_hash.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            code_addr,
            log_stamp,
            topic_left,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, opcode, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 0.into();
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
    #[test]
    fn test_log_topic_log3() {
        let opcode = OpcodeId::LOG3;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94";
        let topic2_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b95";
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x1;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
        let topic_left = 3;

        let stack =
            Stack::from_slice(&[topic2_hash.into(), topic1_hash.into(), topic0_hash.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            code_addr,
            log_stamp,
            topic_left,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, opcode, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 0.into();
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
    #[test]
    fn test_log_topic_log4() {
        let opcode = OpcodeId::LOG4;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b94";
        let topic2_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b95";
        let topic3_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b96";
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x1;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
        let topic_left = 4;

        let stack = Stack::from_slice(&[
            topic3_hash.into(),
            topic2_hash.into(),
            topic1_hash.into(),
            topic0_hash.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            code_addr,
            log_stamp,
            topic_left,
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, opcode, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 0.into();
            row.vers_22 = Some(log_stamp.into());
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
