use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    call_3, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2|                  |
/// | 0 | DYNA_SELECTOR   | AUX | STATE_STAMP_INIT(1) |
/// +---+-------+-------+-------+----------+
///
/// STATE_STAMP_INIT means the state stamp just before the call operation is executed, which is used by the next gadget.

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 2;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at call5

pub struct Call2Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call2Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL2"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_2
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_3::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let call_id_new = state_stamp_init.clone() + 1.expr();
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let mut operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            if i == 0 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    -2.expr(), // the position of value is -2
                    false,
                ));
            } else {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    (state::CallContextTag::Value as u8).expr(),
                    call_id_new.clone(),
                ));
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        constraints.extend([
            (
                "value equal hi".into(),
                operands[0][0].clone() - operands[1][0].clone(),
            ),
            (
                "value equal lo".into(),
                operands[0][1].clone() - operands[1][1].clone(),
            ),
        ]);

        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        constraints.extend([(
            "state_init_for_next_gadget correct".into(),
            stamp_init_for_next_gadget - state_stamp_init,
        )]);

        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // prev call is CALL_1
        // next call is CALL_3
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_1],
                NUM_ROW,
                vec![(ExecutionState::CALL_3, call_3::NUM_ROW, None)],
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
        let call_context_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 1));

        vec![
            ("stack read value".into(), stack_lookup),
            ("callcontext write value".into(), call_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_read_row, value) = current_state.get_peek_stack_row_value(trace, 3);

        let call_context_write_row = current_state.get_call_context_write_row(
            state::CallContextTag::Value,
            value,
            current_state.call_id_new,
        );
        current_state.value.insert(current_state.call_id_new, value);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        core_row_1.insert_state_lookups([&stack_read_row, &call_context_write_row]);
        let mut core_row_0 = ExecutionState::CALL_2.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let stamp_init = current_state.call_id_new - 1; // here we use the property that call_id_new == state_stamp + 1, where state_stamp is the stamp just before call operation is executed (instead of before the call_2 gadget).
        assign_or_panic!(core_row_0.vers_27, stamp_init.into());
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_read_row, call_context_write_row],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call2Gadget {
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
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let state_stamp_init = 3;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row.vers_27 = Some(state_stamp_init.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_3.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            //row.pc = 0.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
