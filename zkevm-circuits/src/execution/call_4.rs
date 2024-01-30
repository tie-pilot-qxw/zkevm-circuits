use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 4;

/// Call4 is the fourth step of opcode CALL.
/// After Call4, there should be execution states of the callee.
/// Algorithm overview:
///     1. read gas, addr from stack (temporarily not popped)
///     2. set call_context's storage_contract_addr = addr, caller = current code_addr
/// Table layout:
///     1. State lookup(stack read gas), src: Core circuit, target: State circuit table, 8 columns
///     2. State lookup(stack read addr), src: Core circuit, target: State circuit table, 8 columns
///     3. State lookup(call_context write storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     4. State lookup(call_context write caller), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call4Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call4Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL4"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_4
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
        let code_addr_cur = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stack_pointer_prev = meta.query_advice(
            stack_pointer,
            Rotation(-1 * NUM_ROW as i32), // call_1， call_2 and call_3 don't change the stack_pointer value, so stack_pointer of the last gadget equals to the stack_pointer just before the call operation.
        );
        let call_id_new = state_stamp_init.clone() + 1.expr();
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(-stack_pointer_prev.expr()), // stack pointer will become 0 after call_4
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append stack constraints and call_context constraints
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            if i < 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    if i == 0 { 0 } else { -1 }.expr(), // the position of gas and addr are 0 and -1 respectively.
                    false,
                ));
            } else {
                constraints.append(
                    &mut config.get_call_context_constraints(
                        meta,
                        entry.clone(),
                        i,
                        NUM_ROW,
                        true,
                        if i == 2 {
                            state::CallContextTag::StorageContractAddr as u8
                        } else {
                            state::CallContextTag::SenderAddr as u8
                        }
                        .expr(),
                        call_id_new.clone(),
                    ),
                );
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state lookup's values
        let addr = operands[1].clone();
        let storage_contract_addr = operands[2].clone();
        let sender_addr = operands[3].clone();

        constraints.extend([
            (
                "storage_contract_addr == addr hi".into(),
                storage_contract_addr[0].clone() - addr[0].clone(),
            ),
            (
                "storage_contract_addr == addr lo".into(),
                storage_contract_addr[1].clone() - addr[1].clone(),
            ),
            (
                "sender_addr == current code_addr ".into(),
                sender_addr[0].clone() * pow_of_two::<F>(128) + sender_addr[1].clone()
                    - code_addr_cur,
            ),
        ]);
        // append opcode constraint
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(call_id_new),
            code_addr: ExpressionOutcome::To(
                addr[0].clone() * pow_of_two::<F>(128) + addr[1].clone(),
            ),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // prev state is CALL_3
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::CALL_3], NUM_ROW, vec![]),
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
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            ("stack read gas".into(), stack_lookup_0),
            ("stack read addr".into(), stack_lookup_1),
            (
                "callcontext write storage_contract_addr".into(),
                call_context_lookup_0,
            ),
            (
                "callcontext write sender_addr".into(),
                call_context_lookup_1,
            ),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // generate stack_read rows
        let (stack_read_0, _gas) = current_state.get_peek_stack_row_value(trace, 1);
        let (stack_read_1, addr) = current_state.get_peek_stack_row_value(trace, 2);
        // generate call_context rows
        let call_context_write_row_0 = current_state.get_call_context_write_row(
            state::CallContextTag::StorageContractAddr,
            addr.into(),
            current_state.call_id_new,
        );
        let call_context_write_row_1 = current_state.get_call_context_write_row(
            state::CallContextTag::SenderAddr,
            current_state.code_addr,
            current_state.call_id_new,
        );
        // update current_state's storage_contract_addr and sender
        current_state
            .storage_contract_addr
            .insert(current_state.call_id_new, addr);
        current_state
            .sender
            .insert(current_state.call_id_new, current_state.code_addr);

        // update current_state's stack_pointer
        current_state.stack_pointer = 0;
        // generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        core_row_1.insert_state_lookups([
            &stack_read_0,
            &stack_read_1,
            &call_context_write_row_0,
            &call_context_write_row_1,
        ]);
        let core_row_0 = ExecutionState::CALL_4.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // update call_id, code_addr
        current_state.call_id = current_state.call_id_new;
        current_state.code_addr = addr;

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                stack_read_0,
                stack_read_1,
                call_context_write_row_0,
                call_context_write_row_1,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call4Gadget {
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
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_3.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[21] = Some(stack_pointer.into());
            row[27] = Some(state_stamp_init.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
