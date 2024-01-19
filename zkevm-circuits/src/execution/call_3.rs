use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    call_4, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 4;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at call5

/// Call3 is the third step of opcode CALL
/// Algorithm overview:
///     1. set call_context's parent_call_id = current call_id
///     2. set call_context's parent_pc = current pc
///     3. set call_context's parent_stack_pointer = current stack_pointer
///     4. set call_context's parent_code_addr = current code_addr
/// Table layout:
///     1. State lookup(call_context write parent_call_id), src: Core circuit, target: State circuit table, 8 columns
///     2. State lookup(call_context write parent_pc), src: Core circuit, target: State circuit table, 8 columns
///     3. State lookup(call_context write parent_stack_pointer), src: Core circuit, target: State circuit table, 8 columns
///     4. State lookup(call_context write parent_code_addr), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX | STATE_STAMP_INIT(1) |
/// +---+-------+-------+-------+----------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call3Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call3Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL3"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_3
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_4::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());
        let pc = meta.query_advice(config.pc, Rotation::cur());
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stack_pointer_prev = meta.query_advice(
            stack_pointer,
            Rotation(-1 * NUM_ROW as i32), // call_1 and call_2 don't change the stack_pointer value, so stack_pointer of the last gadget equals to the stack_pointer just before the call operation.
        );
        let call_id_new = state_stamp_init.clone() + 1.expr();
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append call_context constraints
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);

            constraints.append(
                &mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    if i == 0 {
                        state::CallContextTag::ParentCallId as u8
                    } else if i == 1 {
                        state::CallContextTag::ParentProgramCounter as u8
                    } else if i == 2 {
                        state::CallContextTag::ParentStackPointer as u8
                    } else {
                        state::CallContextTag::ParentCodeContractAddr as u8
                    }
                    .expr(),
                    call_id_new.clone(),
                ),
            );

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state lookup's values
        constraints.extend([
            ("ParentCallId write hi".into(), operands[0][0].clone()),
            (
                "ParentProgramCounter write hi".into(),
                operands[1][0].clone(),
            ),
            ("ParentStackPointer write hi".into(), operands[2][0].clone()),
            (
                "ParentCallId write lo".into(),
                operands[0][1].clone() - call_id_cur,
            ),
            (
                "ParentProgramCounter write lo".into(),
                operands[1][1].clone() - pc,
            ),
            (
                "ParentStackPointer write lo".into(),
                operands[2][1].clone() - stack_pointer_prev,
            ),
            (
                "ParentCodeContractAddr write".into(),
                operands[3][0].clone() * pow_of_two::<F>(128) + operands[3][1].clone() - code_addr,
            ),
        ]);
        // append opcode constraint
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        // append constraint for the next execution state's stamp_init
        constraints.extend([(
            "state_init_for_next_gadget correct".into(),
            stamp_init_for_next_gadget - state_stamp_init,
        )]);
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // prev state is CALL_2, next state is CALL_4
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_2],
                NUM_ROW,
                vec![(ExecutionState::CALL_4, call_4::NUM_ROW, None)],
            ),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let call_context_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            ("ParentCallId write".into(), call_context_lookup_0),
            ("ParentProgramCounter write".into(), call_context_lookup_1),
            ("ParentStackPointer write".into(), call_context_lookup_2),
            ("ParentCodeContractAddr write".into(), call_context_lookup_3),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        //generate call_context rows
        let call_context_write_row_0 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentCallId,
            current_state.call_id.into(),
            current_state.call_id_new,
        );
        let call_context_write_row_1 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentProgramCounter,
            trace.pc.into(),
            current_state.call_id_new,
        );
        let call_context_write_row_2 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentStackPointer,
            current_state.stack_pointer.into(),
            current_state.call_id_new,
        );
        let call_context_write_row_3 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentCodeContractAddr,
            current_state.code_addr.into(),
            current_state.call_id_new,
        );

        //update current_state's parent_call_id, parent_pc, parent_stack_pointer and parent_code_addr
        current_state
            .parent_call_id
            .insert(current_state.call_id_new, current_state.call_id);
        current_state
            .parent_pc
            .insert(current_state.call_id_new, trace.pc);
        current_state
            .parent_stack_pointer
            .insert(current_state.call_id_new, current_state.stack_pointer);
        current_state
            .parent_code_addr
            .insert(current_state.call_id_new, current_state.code_addr);
        //generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        core_row_1.insert_state_lookups([
            &call_context_write_row_0,
            &call_context_write_row_1,
            &call_context_write_row_2,
            &call_context_write_row_3,
        ]);
        let mut core_row_0 = ExecutionState::CALL_3.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // here we use the property that call_id_new == state_stamp + 1, where state_stamp is the stamp just before call operation is executed (instead of before the call_3 gadget).
        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(core_row_0.vers_27, stamp_init.into());
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                call_context_write_row_0,
                call_context_write_row_1,
                call_context_write_row_2,
                call_context_write_row_3,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call3Gadget {
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
        current_state.call_id = 1;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_2.into_exec_state_core_row(
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
            let row = ExecutionState::CALL_4.into_exec_state_core_row(
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
