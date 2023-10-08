use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::util::query_expression;
use crate::witness::{arithmetic, CurrentState, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::default;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 3;

pub struct DivModGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for DivModGadget<F>
{
    fn name(&self) -> &'static str {
        "DIV_MOD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::DIV_MOD
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
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value();
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value();
        let (quotient, reminder) = if b.is_zero() {
            let quotient = 0.into();
            let reminder = 0.into();
            (quotient, reminder)
        } else {
            a.div_mod(b)
        };
        let c = trace.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(c);
        let exp_c: U256 = if current_state.opcode == OpcodeId::DIV {
            quotient
        } else if current_state.opcode == OpcodeId::MOD {
            reminder
        } else {
            panic!("opcode is not DIV or MOD");
        }
        .into();
        assert_eq!(exp_c, c);
        let arithmetic_rows =
            Witness::gen_arithmetic_witness(arithmetic::Tag::DivMod, [a, b, quotient, reminder]);
        let mut core_row_2 = current_state.get_core_row_without_versatile(2);
        core_row_2.insert_arithmetic_lookup(&arithmetic_rows[0]);
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        let core_row_0 = ExecutionState::DIV_MOD.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(DivModGadget {
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
        let stack = Stack::from_slice(&[3.into(), 6.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::DIV,
            stack_top: Some(2.into()),
        };
        current_state.copy_from_trace(&trace);
        let mut padding_begin_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_begin_row.vers_21 = Some(stack_pointer.into());
        let mut padding_end_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
