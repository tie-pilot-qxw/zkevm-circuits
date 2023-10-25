use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;

pub struct EqGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Eq Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// EQ_AUX includes inverse of hi and lo, and equal of hi and lo
/// +---+-------+-------+-------+--------+----------+
/// |cnt| 8 col | 8 col | 8 col | 4 col  | not used |
/// +---+-------+-------+-------+--------|----------+
/// | 1 | STATE | STATE | STATE | EQ_AUX |          |
/// | 0 | DYNA_SELECTOR      | AUX                  |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EqGadget<F>
{
    fn name(&self) -> &'static str {
        "EQ"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::EQ
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
            operands.push([value_hi, value_lo]);
        }

        let a = operands[0].clone();
        let b = operands[1].clone();
        let c = operands[2].clone();
        let hi_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let lo_inv = meta.query_advice(config.vers[25], Rotation::prev());
        let hi_eq = meta.query_advice(config.vers[26], Rotation::prev());
        let lo_eq = meta.query_advice(config.vers[27], Rotation::prev());
        constraints.extend([
            (
                "hi_inv".into(),
                (a[0].clone() - b[0].clone())
                    * (1.expr() - (a[0].clone() - b[0].clone()) * hi_inv.clone()),
            ),
            (
                "lo_inv".into(),
                (a[1].clone() - b[1].clone())
                    * (1.expr() - (a[1].clone() - b[1].clone()) * lo_inv.clone()),
            ),
            (
                "hi_eq".into(),
                1.expr() - (a[0].clone() - b[0].clone()) * hi_inv - hi_eq.clone(),
            ),
            (
                "lo_eq".into(),
                1.expr() - (a[1].clone() - b[1].clone()) * lo_inv - lo_eq.clone(),
            ),
            ("c_hi".into(), c[0].clone()),
            ("c_lo".into(), c[1].clone() - hi_eq * lo_eq),
        ]);

        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::EQ.as_u8().expr()),
            ("next pc".into(), pc_next - pc_cur - PC_DELTA.expr()),
        ]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack pop c".into(), stack_lookup_2),
        ]
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);

        let (stack_pop_1, b) = current_state.get_pop_stack_row_value(&trace);

        assert_eq!(
            current_state.stack_top.unwrap().as_u64(),
            if a == b { 1 } else { 0 }
        );
        let stack_push_0 =
            current_state.get_push_stack_row(trace, current_state.stack_top.unwrap_or_default());

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);

        let a_hi = F::from_u128((a >> 128).as_u128());
        let b_hi = F::from_u128((b >> 128).as_u128());
        let hi_inv =
            U256::from_little_endian((a_hi - b_hi).invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_24 = Some(hi_inv);
        let a_lo = F::from_u128(a.low_u128());
        let b_lo = F::from_u128(b.low_u128());

        let lo_inv =
            U256::from_little_endian((a_lo - b_lo).invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_25 = Some(lo_inv);
        let hi_eq = if a_hi == b_hi { 1 } else { 0 };
        core_row_1.vers_26 = Some(hi_eq.into());
        let lo_eq = if a_lo == b_lo { 1 } else { 0 };
        core_row_1.vers_27 = Some(lo_eq.into());
        let core_row_0 = ExecutionState::EQ.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EqGadget {
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
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::EQ, stack);
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
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
