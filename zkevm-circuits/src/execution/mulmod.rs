use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;
const STACK_POINTER_DELTA: i32 = -2;
const PC_DELTA: u64 = 1;

pub struct MulmodGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// MulMod Execution State layout is as follows
/// where STATE means state table lookup,
/// ARITH means arithmetic table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH  |      |       | n_inv(2) |
/// | 1 | STATE | STATE | STATE |  STATE   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MulmodGadget<F>
{
    fn name(&self) -> &'static str {
        "MULMOD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MULMOD
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

        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
        let mut arithmetic_operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            // i = 0, stack_pointer pop
            // i = 1, -1 pop
            // i = 2, -2 pop -1 - (i - 1)
            // i = 3, -2 push
            let stack_pointer_delta = if i == 0 {
                0
            } else if i == 1 {
                -1
            } else {
                -2
            };
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta.expr(),
                i == 3,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            arithmetic_operands.extend([value_hi, value_lo]);
        }

        let (tag, arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));

        let hi_inv = meta.query_advice(config.vers[30], Rotation(-2));
        let lo_inv = meta.query_advice(config.vers[31], Rotation(-2));

        let n_is_zero_hi = SimpleIsZero::new(&arithmetic_operands[4], &hi_inv, String::from("hi"));
        let n_is_zero_lo = SimpleIsZero::new(&arithmetic_operands[5], &lo_inv, String::from("lo"));

        // if n == 0, then n_is_zero == 1;
        let n_is_zero = n_is_zero_hi.expr() * n_is_zero_lo.expr();

        constraints.extend([(
            "if n == 0, then a in arithmetic == 0".to_string(),
            n_is_zero.clone()
                * (arithmetic_operands_full[0].clone() + arithmetic_operands_full[1].clone()),
        )]);

        constraints.extend((0..2).map(|i| {
            (
                "if n != 0, then a in arithmetic == in state".to_string(),
                (1.expr() - n_is_zero.clone())
                    * (arithmetic_operands_full[i].clone() - arithmetic_operands[i].clone()),
            )
        }));
        constraints.extend((2..8).map(|i| {
            (
                format!("operand[{}] in arithmetic = in state lookup", i),
                arithmetic_operands[i].clone() - arithmetic_operands_full[i].clone(),
            )
        }));

        constraints.extend([
            (
                "opcode".into(),
                opcode.clone() - OpcodeId::MULMOD.as_u8().expr(),
            ),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::Mulmod as u8).expr(),
            ),
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
        let stack_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack pop c".into(), stack_lookup_2),
            ("stack push".into(), stack_lookup_3),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::MULMOD);

        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_2, n) = current_state.get_pop_stack_row_value(&trace);

        let (arithmetic, result) = operation::mulmod::gen_witness(vec![a, b, n]);
        assert_eq!(result[0], current_state.stack_top.unwrap());

        let r = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, r);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic);

        let n_hi = F::from_u128((n >> 128).as_u128());
        let n_lo = F::from_u128(n.low_u128());
        let lo_inv = U256::from_little_endian(n_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        let hi_inv = U256::from_little_endian(n_hi.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_2.vers_30, hi_inv);
        assign_or_panic!(core_row_2.vers_31, lo_inv);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_pop_2, &stack_push_0]);
        let core_row_0 = ExecutionState::MULMOD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_pop_2, stack_push_0],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MulmodGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn test_witness(stack: Stack, stack_pointer: usize, current_state: &mut WitnessExecHelper) {
        let trace = prepare_trace_step!(0, OpcodeId::MULMOD, stack);
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
            prepare_witness_and_prover!(trace, *current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }

    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[5.into(), 4.into(), 3.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(2.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }

    #[test]
    fn assign_and_constraint_zero() {
        let stack = Stack::from_slice(&[0.into(), 4.into(), 3.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        test_witness(stack, stack_pointer, &mut current_state)
    }
}
