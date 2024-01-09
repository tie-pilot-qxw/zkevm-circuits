use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    call_2, Auxiliary, AuxiliaryDelta, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{assign_or_panic, copy, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY  |                          |
/// | 1 | STATE1| STATE2| STATE3|LEN_INV(1)|
/// | 0 | DYNA_SELECTOR   | AUX | STATE_STAMP_INIT(1) |
/// +---+-------+-------+-------+----------+
///
/// STATE_STAMP_INIT means the state stamp just before the call operation is executed, which is used by the next gadget.

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: usize = 3;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at call5

pub struct Call1Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call1Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_1"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_1
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, super::call_2::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        let call_id_new = state_stamp_prev.clone() + 1.expr();

        let copy_entry = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());

        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let mut operands = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            if i < 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    if i == 0 { -3 } else { -4 }.expr(), // the position of args_offset and args_len are -3 and -4 respectively.
                    false,
                ));
            } else {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    (state::CallContextTag::CallDataSize as u8).expr(),
                    call_id_new.clone(),
                ));
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let args_offset = &operands[0];
        let args_len = &operands[1];
        let calldata_size = &operands[2];

        constraints.extend([
            ("offset_hi == 0".into(), args_offset[0].clone()),
            ("len_hi == 0".into(), args_len[0].clone()),
            ("calldata_size_hi == 0".into(), calldata_size[0].clone()),
            (
                "len_lo == calldata_size_lo".into(),
                args_len[1].clone() - calldata_size[1].clone(),
            ),
        ]);

        let len_lo_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let is_zero_len = SimpleIsZero::new(&args_len[1], &len_lo_inv, String::from("length_lo"));

        constraints.append(&mut is_zero_len.get_constraints());

        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 2));
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Memory,
            call_id_cur,
            args_offset[1].clone(),
            // +1.expr() after state row is generated, the stamp+=1 affected, thus subsequent copy_row start at stamp+=1.
            stamp.clone() + 1.expr(),
            copy::Tag::Calldata,
            call_id_new,
            0.expr(),
            stamp + args_len[1].clone() + 1.expr(),
            None,
            args_len[1].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));

        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        constraints.extend([(
            "state_init_for_next_gadget correct".into(),
            stamp_init_for_next_gadget - state_stamp_prev,
        )]);

        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        // next state is CALL_2 constraints
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::CALL_2, call_2::NUM_ROW, None)],
            ),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));

        vec![
            ("stack read args_offset".into(), stack_lookup_0),
            ("stack read args_len".into(), stack_lookup_1),
            ("write calldatasize".into(), call_context_lookup),
            ("calldata copy lookup".into(), copy_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        current_state.call_id_new = current_state.state_stamp + 1;
        let stamp_init = current_state.state_stamp;

        let (stack_read_0, args_offset) = current_state.get_peek_stack_row_value(trace, 4);
        let (stack_read_1, args_len) = current_state.get_peek_stack_row_value(trace, 5);

        let call_context_write_row = current_state.get_call_context_write_row(
            state::CallContextTag::CallDataSize,
            args_len,
            current_state.call_id_new,
        );
        current_state
            .call_data_size
            .insert(current_state.call_id_new, args_len);

        let (copy_rows, mut state_rows) = current_state.get_calldata_write_rows::<F>(
            trace,
            args_offset.as_usize(),
            args_len.as_usize(),
        );

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        if args_len.is_zero() {
            core_row_2.insert_copy_lookup(
                &copy::Row {
                    byte: 0.into(),
                    src_type: copy::Tag::default(),
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::default(),
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: 0.into(),
                    len: 0.into(),
                    acc: 0.into(),
                },
                None,
            );
        } else {
            core_row_2.insert_copy_lookup(copy_rows.get(0).unwrap(), None);
        }

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([&stack_read_0, &stack_read_1, &call_context_write_row]);

        let len_lo = F::from_u128(args_len.low_u128());
        let lenlo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_1.vers_24, lenlo_inv);

        let mut core_row_0 = ExecutionState::CALL_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        assign_or_panic!(core_row_0.vers_27, stamp_init.into());

        state_rows.extend([stack_read_0, stack_read_1, call_context_write_row]);
        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call1Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[
            0x05.into(),
            0x2222.into(),
            0x04.into(),
            0x1111.into(),
            0x01.into(),
            0x1234.into(),
            0x01.into(),
        ]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 4];

        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::CALL, stack);
        trace.memory.0 = vec![0; 0x1114];
        for i in 0..4 {
            trace.memory.0.insert(0x1111 + i, value_vec[i]);
        }

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
            let mut row = ExecutionState::CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
