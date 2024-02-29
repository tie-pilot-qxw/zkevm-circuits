use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;

const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = 1;
const PC_DELTA: u64 = 1;

/// ReturnDataSize writes the size of the returned data from the last external call to the stack.
/// ReturnDataSize algorithm overview：
///    1.read call_context's returndata_call_id
///    2.read call_context's returndata_size by returndata_call_id
///    2.write returndata_size to stack
/// Table layout:
///     STATE1:  State lookup(call_context read returndata_call_id), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(call_context read returndata_size), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  stack lookup(memory_write), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3|          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
/// Note:
///     1.In STATE1, callid=None (0); value_hi,lo is callid; usually value_hi is 0 and we can constraint "value_hi=0".
///     2.In STATE2, callid=value_lo of STATE1; value_hi,lo is result.
///     3.In STATE3, value hi,lo is STATE2's.
pub struct ReturnDataSizeGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ReturnDataSizeGadget<F>
{
    fn name(&self) -> &'static str {
        "RETURNDATASIZE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::RETURNDATASIZE
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
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        // append stack constraints and call_context constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let mut operands: Vec<[Expression<F>; 2]> = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);

            if i == 0 {
                constraints.append(&mut config.get_returndata_call_id_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                ))
            } else if i == 1 {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    (state::CallContextTag::ReturnDataSize as u8).expr(),
                    operands[0][1].clone(),
                ))
            } else if i == 2 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    1.expr(),
                    true,
                ));
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state_lookup's values
        let returndata_call_id = operands[0].clone();
        let size_read = operands[1].clone();
        let size_write = operands[2].clone();
        constraints.extend([
            (
                format!("returndata_call_id hi == 0"),
                returndata_call_id[0].clone(),
            ),
            (
                format!("size equal hi"),
                size_read[0].clone() - size_write[0].clone(),
            ),
            (
                format!("size equal lo"),
                size_read[1].clone() - size_write[1].clone(),
            ),
        ]);
        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            opcode - OpcodeId::RETURNDATASIZE.as_u8().expr(),
        )]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let returndata_call_id_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let returndata_size_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        vec![
            ("ReturnDataCallId".into(), returndata_call_id_lookup),
            ("ReturnDataSize".into(), returndata_size_lookup),
            ("stack push".into(), stack_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        //generate call_context rows
        let returndata_call_id_0 = current_state.get_returndata_call_id_row();
        let (returndata_size_0, returndata_size) = current_state.get_returndata_size_row();
        //generate stack_push row
        let stack_push_0 = current_state.get_push_stack_row(trace, returndata_size);
        //generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([&returndata_call_id_0, &returndata_size_0, &stack_push_0]);
        let core_row_0 = ExecutionState::RETURNDATASIZE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![returndata_call_id_0, returndata_size_0, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ReturnDataSizeGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::INDEX_STACK_POINTER;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let result = U256::from(3);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(result),
            returndata_call_id: 0xffff,
            returndata_size: U256::from(3),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::RETURNDATASIZE, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + INDEX_STACK_POINTER] =
                Some(stack_pointer.into());
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
        prover.assert_satisfied_par();
    }
}
