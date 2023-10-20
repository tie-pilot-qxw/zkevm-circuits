use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::util::query_expression;
use crate::witness::CurrentState;
use crate::witness::{core, state, Witness};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i64 = 1;

pub struct DupGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Dup Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE | STATE |       |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for DupGadget<F>
{
    fn name(&self) -> &'static str {
        "DUP"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::DUP
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
        vec![]
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert!(current_state.opcode.is_dup());
        let (stack_read, value) = current_state
            .get_peek_stack_row_value(current_state.opcode.postfix().unwrap() as usize);
        assert_eq!(value, current_state.stack_top.unwrap());
        let stack_push = current_state.get_push_stack_row(value);
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_read, &stack_push]);
        let core_row_0 = ExecutionState::DUP.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row_1, core_row_0],
            exp: vec![],
            public: vec![],
            state: vec![stack_read, stack_push],
            arithmetic: vec![],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(DupGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::from_slice(&[0xcc.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };
        // prepare a trace
        let trace = Trace {
            pc: 0,
            op: OpcodeId::DUP1,
            stack_top: Some(0xcc.into()),
        };
        current_state.update(&trace);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 2.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
