// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{
    Auxiliary, AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{assign_or_panic, copy, public, Witness, WitnessExecHelper};

use crate::util::{query_expression, ExpressionOutcome};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{pow_of_two, Expr};
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

        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());

        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());

        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());

        let Auxiliary { log_stamp, .. } = config.get_auxiliary();
        let log_stamp = meta.query_advice(log_stamp, Rotation(NUM_ROW as i32 * -1));

        // build constraints ---
        // append auxiliary constraints
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            log_stamp: LOG_STAMP_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // new selector LOG_LEFT_X and append selector constraints
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[8], Rotation::prev()), // LOG_LEFT_4
            meta.query_advice(config.vers[9], Rotation::prev()), // LOG_LEFT_3
            meta.query_advice(config.vers[10], Rotation::prev()), // LOG_LEFT_2
            meta.query_advice(config.vers[11], Rotation::prev()), // LOG_LEFT_1
            meta.query_advice(config.vers[12], Rotation::prev()), // LOG_LEFT_0
        ]);
        constraints.extend(selector.get_constraints());

        // append stack constraints
        let mut stack_pop_values = vec![];
        let mut stamp_start = 0.expr();

        for i in 0..1 {
            let state_entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                state_entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, stamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);
            stack_pop_values.push(value_hi); // 0
            stack_pop_values.push(value_lo);
            if i == 1 {
                stamp_start = stamp;
            }
        }

        // append core single purpose constraints
        let delta = CoreSinglePurposeOutcome {
            // pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

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
                format!("public log_stamp is correct").into(),
                public_values[0].clone() - log_stamp,
            ),
            (
                format!("public log tag is addrWithXLog").into(),
                public_values[1].clone() - (opcode.clone() - (OpcodeId::LOG0).as_u8().expr()),
            ),
            (
                format!("public log addr hi and lo is code_addr").into(),
                public_values[2].clone() * pow_of_two::<F>(128) + public_values[3].clone()
                    - code_addr,
            ),
        ]);

        // extend opcode and pc constraints
        constraints.extend([
            (
                "opcode is correct refer to LOG_LEFT_X".into(),
                selector.select(&[
                    opcode.clone() - OpcodeId::LOG4.as_u8().expr(),
                    opcode.clone() - OpcodeId::LOG3.as_u8().expr(),
                    opcode.clone() - OpcodeId::LOG2.as_u8().expr(),
                    opcode.clone() - OpcodeId::LOG1.as_u8().expr(),
                    opcode.clone() - OpcodeId::LOG0.as_u8().expr(),
                ]),
            ),
            (
                format!("next pc +1 only when LOG_LEFT_0").into(),
                selector.select(&[
                    pc_next.clone() - pc_cur.clone(),
                    pc_next.clone() - pc_cur.clone(),
                    pc_next.clone() - pc_cur.clone(),
                    pc_next.clone() - pc_cur.clone(),
                    pc_next - pc_cur - PC_DELTA.expr(),
                ]),
            ),
        ]);

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
        // get topic from stack top
        let (stack_pop_topic, topic) = current_state.get_pop_stack_row_value(&trace);

        // core_row_1: state lookup (vers_0~vers_7) + selector LOG_LEFT_X (vers_8~vers_12) + Public Log LookUp (vers_26~vers_31)
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // core_row_1: insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&stack_pop_topic]);

        // core_row_1: insert selector LOG_LEFT_4, LOG_LEFT_3, LOG_LEFT_2, LOG_LEFT_1, LOG_LEFT_0
        simple_selector_assign(
            [
                &mut core_row_1.vers_12, // LOG_LEFT_0
                &mut core_row_1.vers_11, // LOG_LEFT_1
                &mut core_row_1.vers_10, // LOG_LEFT_2
                &mut core_row_1.vers_9,  // LOG_LEFT_3
                &mut core_row_1.vers_8,  // LOG_LEFT_4
            ],
            current_state.log_left, // if log_left is X, then the location for LOG_LEFT_X is assigned by 1
            |cell, value| assign_or_panic!(*cell, value.into()),
        );
        core_row_1.comments.extend([
            ("vers_8".into(), "LOG_LEFT_4 Selector (0/1)".into()),
            ("vers_9".into(), "LOG_LEFT_3 Selector (0/1)".into()),
            ("vers_10".into(), "LOG_LEFT_2 Selector (0/1)".into()),
            ("vers_11".into(), "LOG_LEFT_1 Selector (0/1)".into()),
            ("vers_12".into(), "LOG_LEFT_0 Selector (0/1)".into()),
        ]);

        // core_row_1: insert Public lookUp: Core ----> addrWithXLog  to core_row_1.vers_26 ~ vers_31
        let public_row = current_state.get_public_log_topic_row(trace.op);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_public_lookup(&public_row);

        // increase log_stamp
        current_state.log_stamp += 1;

        let core_row_0 = ExecutionState::LOG_TOPIC.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![stack_pop_topic];

        // decrease log_left
        if current_state.log_left > 0 {
            current_state.log_left -= 1;
        }

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
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        // topic0='t0', topic1='t01', topic2='t02', topic3='t03', topic4='t04'
        let stack =
            Stack::from_slice(&[0x7430.into(), 0x7431.into(), 0x7432.into(), 0x7430.into()]);
        let stack_pointer = stack.0.len();
        let call_id: u64 = 0x33;
        let tx_idx = 0x44;
        let log_stamp = 0x55;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
            log_stamp,
            code_addr,
            log_left: 4,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::LOG4, stack);
        trace.memory.push("hello");

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
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
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
