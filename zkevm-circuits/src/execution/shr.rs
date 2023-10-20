use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{arithmetic, exp, CurrentState, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;

pub struct ShrGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ShrGadget<F>
{
    fn name(&self) -> &'static str {
        "SHR"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SHR
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
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let mut operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.extend([value_hi, value_lo]);
        }
        let (tag, arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta));

        constraints.extend([
            (
                "arithmetic operand 0 hi".into(),
                operands[2].clone() - arithmetic_operands_full[0].clone(),
            ),
            (
                "arithmetic operand 0 lo".into(),
                operands[3].clone() - arithmetic_operands_full[1].clone(),
            ),
            (
                "arithmetic operand 2 lo".into(),
                operands[4].clone() - arithmetic_operands_full[4].clone(),
            ),
            (
                "arithmetic operand 2 lo".into(),
                operands[5].clone() - arithmetic_operands_full[5].clone(),
            ),
        ]);
        let entry = config.get_exp_lookup(meta);
        let (base, index, power) = extract_lookup_expression!(exp, entry);
        constraints.extend([
            ("base hi".into(), base[0].clone()),
            ("base lo".into(), base[1].clone() - 2.expr()),
            ("index hi".into(), index[0].clone() - operands[0].clone()),
            ("index lo".into(), index[1].clone() - operands[1].clone()),
            (
                "power equals div num hi".into(),
                power[0].clone() - arithmetic_operands_full[2].clone(),
            ),
            (
                "power equals div num lo".into(),
                power[1].clone() - arithmetic_operands_full[3].clone(),
            ),
        ]);
        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::SHR.as_u8().expr()),
            ("next pc".into(), pc_next - pc_cur - PC_DELTA.expr()),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::DivMod as u8).expr(),
            ),
        ]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("exp lookup".into(), exp_lookup),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value();
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value();
        let c = trace.stack_top.unwrap_or_default();
        assert_eq!(if a > 256.into() { 0.into() } else { b >> a }, c);

        let stack_push_0 = current_state.get_push_stack_row(c);
        let div_num = if a > 256.into() {
            0.into()
        } else {
            U256::from(1) << a
        };

        let arithmetic_rows = Witness::gen_arithmetic_witness(
            arithmetic::Tag::DivMod,
            [b, div_num, c, b - div_num * c],
        );
        let mut core_row_2 = current_state.get_core_row_without_versatile(2);
        core_row_2.insert_arithmetic_lookup(&arithmetic_rows[0]);
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        core_row_1.insert_exp_lookup(U256::from(2), a, div_num);
        let core_row_0 = ExecutionState::SHR.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let exp_rows = exp::Row::from_operands(U256::from(2), a, div_num);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            exp: exp_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ShrGadget {
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
        let stack = Stack::from_slice(&[0x20.into(), 4.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::SHR,
            stack_top: Some(2.into()),
        };
        current_state.copy_from_trace(&trace);
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
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
