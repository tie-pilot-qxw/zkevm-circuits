use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};

use crate::witness::{assign_or_panic, copy, public, Witness, WitnessExecHelper};

use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::LogTag;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// core rows
/// LogBytes Execution State layout is as follows
/// where COPY means copy table lookup , 9 cols
/// PUBLIC means public table lookup 6 cols, origin from col 26
/// STATE means state table lookup,
/// LO_INV means length's inv , 1 col, located at col 24
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+---------+---------+
/// |cnt| 8 col | 8 col |  8 col  |  8col   |
/// +---+-------+-------+---------+---------+
/// | 2 | Copy(9) |9col(not used)| PUBLIC(6) |
/// | 1 | STATE | STATE | notUsed | LO_INV(1 col) |
/// | 0 | DYNA_SELECTOR | AUX               |
/// +---+-------+-------+---------+---------+
///

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = -2;
const PC_DELTA: u64 = 0;

pub struct LogBytesGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LogBytesGadget<F>
{
    fn name(&self) -> &'static str {
        "LOG_BYTES"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LOG_BYTES
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let Auxiliary { log_stamp, .. } = config.get_auxiliary();
        let log_stamp = meta.query_advice(log_stamp, Rotation(NUM_ROW as i32 * -1));

        // build constraints ---
        // append auxiliary constraints
        let copy_entry = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr() + len.clone()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // append stack constraints
        let mut stack_pop_values = vec![];
        let mut stamp_start = 0.expr();
        for i in 0..2 {
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
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        // append log_bytes constraints
        let len_lo_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let is_zero_len =
            SimpleIsZero::new(&stack_pop_values[3], &len_lo_inv, String::from("length_lo"));

        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 1));

        constraints.append(&mut is_zero_len.get_constraints());
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Memory,
            call_id,
            stack_pop_values[1].clone(),
            stamp_start + 1.expr(),
            copy::Tag::PublicLog,
            tx_idx.clone(),
            0.expr(),          // index of PublicLog
            log_stamp.clone(), // log_stamp from Auxiliary
            None,
            stack_pop_values[3].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));

        // append addrWithXLog constraints
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
                format!("public log tag is DataSize").into(),
                public_values[1].clone() - (LogTag::DataSize as u8).expr(),
            ),
            (
                format!("public values[2] is 0").into(),
                public_values[2].clone(),
            ),
            (
                format!("public data_len is length").into(),
                public_values[3].clone() - len.clone(),
            ),
        ]);

        // extend opcode and pc constraints
        constraints.extend([(
            format!("opcode is one of LOG0,LOG1,LOG2,LOG3,LOG4").into(),
            (opcode.clone() - (OpcodeId::LOG0).expr())
                * (opcode.clone() - (OpcodeId::LOG1).expr())
                * (opcode.clone() - (OpcodeId::LOG2).expr())
                * (opcode.clone() - (OpcodeId::LOG3).expr())
                * (opcode - (OpcodeId::LOG4).expr()),
        )]);

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta));

        vec![
            (
                "state lookup, stack pop lookup offset".into(),
                stack_lookup_0,
            ),
            (
                "state lookup, stack pop lookup length".into(),
                stack_lookup_1,
            ),
            ("code copy lookup".into(), copy_lookup),
            ("public lookup".into(), public_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get offset、length from stack top
        // let (stack_pop_dst_offset, dst_offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_offset, offset) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_length, length) = current_state.get_pop_stack_row_value(&trace);

        // generate core rows
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // generate copy rows and state rows(type: memory)
        let (copy_rows, memory_state_rows) =
            current_state.get_log_bytes_rows::<F>(trace, offset.as_usize(), length.as_usize());

        // insert lookUp: Core ---> Copy
        if length.is_zero() {
            core_row_2.insert_copy_lookup(&Default::default(), None);
        } else {
            core_row_2.insert_copy_lookup(&copy_rows[0], None);
        }

        // write addrWithXLog to core_row_2.vers_26 ~ vers_31
        // insert lookUp: Core ----> addrWithXLog
        let public_row = current_state.get_public_log_data_size_row(length);
        core_row_2.insert_public_lookup(&public_row);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        let len_lo = F::from_u128(length.as_u128());
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        // core_row_1.vers_24 = Some(len_lo_inv);
        assign_or_panic!(core_row_1.vers_24, len_lo_inv);

        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            // &stack_pop_dst_offset,
            &stack_pop_offset,
            &stack_pop_length,
        ]);

        let core_row_0 = ExecutionState::LOG_BYTES.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_rows = vec![stack_pop_offset, stack_pop_length];
        state_rows.extend(memory_state_rows);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(LogBytesGadget {
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
    fn test_log_bytes_log0() {
        let opcode = OpcodeId::LOG0;
        let offset: u64 = 0x1;
        let length: u64 = 0x4;
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x0;
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");

        let stack = Stack::from_slice(&[length.into(), offset.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
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

    #[test]
    fn test_log_bytes_log1() {
        let opcode = OpcodeId::LOG1;
        let offset: u64 = 0x1;
        let length: u64 = 0x4;
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x1;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");

        let stack = Stack::from_slice(&[topic0_hash.into(), length.into(), offset.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
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

    #[test]
    fn test_log_bytes_log2() {
        let opcode = OpcodeId::LOG2;
        let offset: u64 = 0x1;
        let length: u64 = 0x4;
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x2;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");

        let stack = Stack::from_slice(&[
            topic1_hash.into(),
            topic0_hash.into(),
            length.into(),
            offset.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
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

    #[test]
    fn test_log_bytes_log3() {
        let opcode = OpcodeId::LOG3;
        let offset: u64 = 0x1;
        let length: u64 = 0x4;
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x4;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic2_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");

        let stack = Stack::from_slice(&[
            topic2_hash.into(),
            topic1_hash.into(),
            topic0_hash.into(),
            length.into(),
            offset.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            call_id,
            tx_idx,
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

    #[test]
    fn test_log_bytes_log4() {
        let opcode = OpcodeId::LOG4;
        let offset: u64 = 0x1;
        let length: u64 = 0x4;
        let call_id: u64 = 0xa;
        let tx_idx = 0xb;
        let log_stamp = 0x4;
        let topic0_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic1_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic2_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let topic3_hash = "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93";
        let code_addr = U256::from("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");

        let stack = Stack::from_slice(&[
            topic3_hash.into(),
            topic2_hash.into(),
            topic1_hash.into(),
            topic0_hash.into(),
            length.into(),
            offset.into(),
        ]);
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
