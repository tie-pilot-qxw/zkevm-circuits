use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const EQ_STATE_STAMP_DELTA: u64 = 3;
const EQ_STACK_POINTER_DELTA: i32 = -1;
const ISZERO_STATE_STAMP_DELTA: u64 = 2;
const ISZERO_STACK_POINTER_DELTA: i32 = 0;
const PC_DELTA: u64 = 1;
const START_COL_IDX: usize = 24;
const INV_EQ_AUX_WIDTH: usize = 4;

pub struct IsZeroEqGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// IsZeroEqGadget Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// IN_EQ_AUX includes inverse of hi and lo, and equal of hi and lo
/// TAG_SEL, 2 columns, depends on opcode of iszero or eq , value can only be 1 or 0
/// +---+-------+-------+-------+--------+----------+---------+
/// |cnt| 8 col | 8 col | 8 col | 4 col  | 2 col    |not used |
/// +---+-------+-------+-------+--------|----------+---------+
/// | 1 | STATE | STATE | STATE |IN_EQ_AU|  TAG_SEL |         |
/// | 0 | DYNA_SELECTOR      | AUX                            |
/// +---+-------+-------+-------+--------|----------|---------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for IsZeroEqGadget<F>
{
    fn name(&self) -> &'static str {
        "ISZERO_EQ"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ISZERO_EQ
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
        let selector = SimpleSelector::new(&[
            meta.query_advice(
                config.vers[START_COL_IDX + INV_EQ_AUX_WIDTH],
                Rotation::prev(),
            ),
            meta.query_advice(
                config.vers[START_COL_IDX + INV_EQ_AUX_WIDTH + 1],
                Rotation::prev(),
            ),
        ]);
        // get state stamp delta according to selector
        let state_stamp_delta =
            selector.select(&[ISZERO_STATE_STAMP_DELTA.expr(), EQ_STATE_STAMP_DELTA.expr()]);
        // get stack pointer delta according to selector
        let stack_pointer_delta = selector.select(&[
            ISZERO_STACK_POINTER_DELTA.expr(),
            EQ_STACK_POINTER_DELTA.expr(),
        ]);
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(state_stamp_delta),
            stack_pointer: ExpressionOutcome::Delta(stack_pointer_delta.clone()),
            // eq and is_zero's const_gas is same
            gas_left: ExpressionOutcome::Delta(OpcodeId::EQ.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta.clone());
        // selector constraints
        constraints.extend(selector.get_constraints());
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, delta));

        let mut operands = vec![];
        //let stack_pointer_delta = vec![0, -1, -1];
        let stack_pointer_deltas = vec![0.expr(), -1.expr(), stack_pointer_delta];
        let state_stamp_deltas = vec![0.expr(), 1.expr(), selector.select(&[1.expr(), 2.expr()])];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            if i == 1 {
                constraints.append(&mut config.get_stack_constraints_with_state_default(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    stack_pointer_deltas[i].clone(),
                    state_stamp_deltas[i].clone(),
                    selector.select(&[1.expr(), 0.expr()]),
                    i == 2,
                ))
            } else {
                constraints.append(&mut config.get_stack_constraints_with_state_default(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    stack_pointer_deltas[i].clone(),
                    state_stamp_deltas[i].clone(),
                    0.expr(),
                    i == 2,
                ));
            }

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let a = operands[0].clone();
        let b = operands[1].clone();
        let c = operands[2].clone();
        let hi_inv = meta.query_advice(config.vers[START_COL_IDX], Rotation::prev());
        let lo_inv = meta.query_advice(config.vers[START_COL_IDX + 1], Rotation::prev());
        let hi_eq = meta.query_advice(config.vers[START_COL_IDX + 2], Rotation::prev());
        let lo_eq = meta.query_advice(config.vers[START_COL_IDX + 3], Rotation::prev());
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
            (
                "opcode".into(),
                selector.select(&[
                    opcode.clone() - OpcodeId::ISZERO.as_u8().expr(),
                    opcode.clone() - OpcodeId::EQ.as_u8().expr(),
                ]),
            ),
            ("next pc".into(), pc_next - pc_cur - PC_DELTA.expr()),
        ]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // stack pop 0
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        // stack pop 1 row or default state row
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        // stack push 0 row
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push c".into(), stack_lookup_2),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);
        // if eq, get stack pop row
        // if is zero ,get default state row(all column value is 0)
        let (stack_pop_1, b) = match trace.op {
            OpcodeId::EQ => current_state.get_pop_stack_row_value(&trace),
            OpcodeId::ISZERO => (state::Row::default(), U256::zero()),
            _ => panic!("not is_zero, eq"),
        };
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
        let a_lo = F::from_u128(a.low_u128());
        let b_lo = F::from_u128(b.low_u128());
        let lo_inv =
            U256::from_little_endian((a_lo - b_lo).invert().unwrap_or(F::ZERO).to_repr().as_ref());
        let hi_eq = if a_hi == b_hi { 1 } else { 0 };
        let lo_eq = if a_lo == b_lo { 1 } else { 0 };
        // assign inverse eq aux columns
        let column_values = [hi_inv, lo_inv, hi_eq.into(), lo_eq.into()];
        for i in 0..INV_EQ_AUX_WIDTH {
            assign_or_panic!(core_row_1[i + START_COL_IDX], column_values[i]);
        }
        // assign simple selector
        // if is zero, state_rows = [stack_pop_0, stack_push_0],do not include state default row
        // if eq, state_rows = [stack_pop_0, stack_pop_1, stack_push_0]
        let (state_rows, index) = match trace.op {
            OpcodeId::ISZERO => (vec![stack_pop_0, stack_push_0], 0usize),
            OpcodeId::EQ => (vec![stack_pop_0, stack_pop_1, stack_push_0], 1usize),
            _ => panic!("not is_zero, eq"),
        };
        simple_selector_assign(
            &mut core_row_1,
            [
                START_COL_IDX + INV_EQ_AUX_WIDTH,
                START_COL_IDX + INV_EQ_AUX_WIDTH + 1,
            ],
            index,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::ISZERO_EQ.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: state_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(IsZeroEqGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(opcode: OpcodeId, stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + opcode.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, opcode, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(U256::from(gas_left_before_exec));
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

    #[test]
    fn test_not_eq() {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_top = U256::zero();
        run(OpcodeId::EQ, stack, stack_top);
    }
    #[test]
    fn test_eq() {
        let stack = Stack::from_slice(&[1.into(), 1.into()]);
        let stack_top = U256::one();
        run(OpcodeId::EQ, stack, stack_top);
    }

    #[test]
    fn test_is_zero() {
        let stack = Stack::from_slice(&[0.into()]);
        let stack_top = U256::one();
        run(OpcodeId::ISZERO, stack, stack_top);
    }

    #[test]
    fn test_is_not_zero() {
        let stack = Stack::from_slice(&[1.into()]);
        let stack_top = U256::zero();
        run(OpcodeId::ISZERO, stack, stack_top);
    }
}
