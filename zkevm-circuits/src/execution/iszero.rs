use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{arithmetic, WitnessExecHelper};
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::thread::current;

const NUM_ROW: usize = 2;

const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = 0;
const PC_DELTA: u64 = 1;

pub struct IszeroGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for IszeroGadget<F>
{
    fn name(&self) -> &'static str {
        "ISZERO"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ISZERO
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

        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                0.expr(),
                i == 1,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let a = operands[0].clone();
        let b = operands[1].clone();
        let hi_inv = meta.query_advice(config.vers[16], Rotation::prev());
        let lo_inv = meta.query_advice(config.vers[17], Rotation::prev());
        let hi_iszero = meta.query_advice(config.vers[18], Rotation::prev());
        let lo_iszero = meta.query_advice(config.vers[19], Rotation::prev());

        let iszero_gadget_hi = SimpleIsZero::new(&a[0], &hi_inv, String::from("hi"));
        let iszero_gadget_lo = SimpleIsZero::new(&a[1], &lo_inv, String::from("lo"));

        let expr_hi = iszero_gadget_hi.expr();
        let expr_lo = iszero_gadget_lo.expr();

        constraints.extend(iszero_gadget_hi.get_constraints());
        constraints.extend(iszero_gadget_lo.get_constraints());

        constraints.extend([
            ("hi_iszero".into(), expr_hi - hi_iszero.clone()),
            ("lo_iszero".into(), expr_lo - lo_iszero.clone()),
            ("hi_ans".into(), b[0].clone()),
            ("lo_ans".into(), b[1].clone() - hi_iszero * lo_iszero),
        ]);

        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::ISZERO.as_u8().expr()),
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
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack push b".into(), stack_lookup_1),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);

        assert_eq!(
            current_state.stack_top.unwrap().as_u64(),
            if a == U256::from(0) { 1 } else { 0 }
        );

        let stack_push_0 =
            current_state.get_push_stack_row(trace, current_state.stack_top.unwrap_or_default());

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);

        let a_hi = F::from_u128((a >> 128).as_u128());
        let hi_inv = U256::from_little_endian(a_hi.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_16 = Some(hi_inv);
        let a_lo = F::from_u128(a.low_u128());
        let lo_inv = U256::from_little_endian(a_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_17 = Some(lo_inv);
        let hi_iszero = if a_hi == F::from_u128(0) { 1 } else { 0 };
        core_row_1.vers_18 = Some(hi_iszero.into());
        let lo_iszero = if a_lo == F::from_u128(0) { 1 } else { 0 };
        core_row_1.vers_19 = Some(lo_iszero.into());

        let core_row_0 = ExecutionState::ISZERO.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(IszeroGadget {
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
        let stack = Stack::from_slice(&[0.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(1.into()),
            ..WitnessExecHelper::new()
        };

        let trace = prepare_trace_step!(0, OpcodeId::ISZERO, stack);

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
