use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::{GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = -2;
const HI_INV_COLUMN_ID: usize = 16;
const LO_INV_COLUMN_ID: usize = 17;
const HI_ZERO_COLUMN_ID: usize = 18;
const LO_ZERO_COLUMN_ID: usize = 19;
const HI_LO_ZERO_COLUMN_ID: usize = 20;
pub struct JumpiGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Jumpi Execution State layout is as follows
/// where STATE means state table lookup,
/// BYTEFULL means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE | STATE |STATE   | BYTEFULL |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for JumpiGadget<F>
{
    fn name(&self) -> &'static str {
        "JUMPI"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::JUMPI
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
        let expect_next_pc = meta.query_advice(config.pc, Rotation::next());
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
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
                if i == 0 { 0 } else { -1 }.expr(),
                false,
            ));

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);

            operands.extend([value_hi.clone(), value_lo.clone()]);
            if i == 0 {
                //value_a_hi = 0
                constraints.extend([("operand0hi=0".into(), value_hi.clone())])
            }
        }

        let (
            bytecode_full_lookup_addr,
            bytecode_full_lookup_pc,
            bytecode_full_lookup_op,
            bytecode_full_lookup_not_code,
            _,
            _,
            _,
            _,
        ) = extract_lookup_expression!(bytecode, config.get_bytecode_full_lookup(meta));

        let hi_inv = meta.query_advice(config.vers[HI_INV_COLUMN_ID], Rotation::prev());
        let lo_inv = meta.query_advice(config.vers[LO_INV_COLUMN_ID], Rotation::prev());
        let hi_is_zero = meta.query_advice(config.vers[HI_ZERO_COLUMN_ID], Rotation::prev());
        let lo_is_zero = meta.query_advice(config.vers[LO_ZERO_COLUMN_ID], Rotation::prev());
        let is_zero = meta.query_advice(config.vers[HI_LO_ZERO_COLUMN_ID], Rotation::prev());

        let iszero_gadget_hi = SimpleIsZero::new(&operands[2], &hi_inv, String::from("hi"));
        let iszero_gadget_lo = SimpleIsZero::new(&operands[3], &lo_inv, String::from("lo"));

        constraints.extend([
            (
                "opcode is JumpI".into(),
                opcode - OpcodeId::JUMPI.as_u8().expr(),
            ),
            (
                "is_zero of operand1hi".into(),
                iszero_gadget_hi.expr() - hi_is_zero.clone(),
            ),
            (
                "is_zero of operand1lo".into(),
                iszero_gadget_lo.expr() - lo_is_zero.clone(),
            ),
            (
                "is_zero of operand1".into(),
                is_zero.clone() - hi_is_zero * lo_is_zero,
            ),
            (
                "expect next pc".into(),
                expect_next_pc.clone()
                    - (pc_cur.clone() + 1.expr()) * is_zero.clone()
                    - (1.expr() - is_zero.clone()) * operands[1].clone(),
            ),
            (
                "bytecode lookup addr = code_addr".into(),
                (1.expr() - is_zero.clone()) * (code_addr - bytecode_full_lookup_addr.clone())
                    + is_zero.clone() * bytecode_full_lookup_addr,
            ),
            (
                "bytecode lookup pc = expect_next_pc".into(),
                (1.expr() - is_zero.clone()) * (bytecode_full_lookup_pc.clone() - expect_next_pc)
                    + is_zero.clone() * bytecode_full_lookup_pc,
            ),
            (
                "bytecode lookup opcode = JUMPDEST".into(),
                (1.expr() - is_zero.clone())
                    * (bytecode_full_lookup_op.clone() - OpcodeId::JUMPDEST.as_u8().expr())
                    + is_zero.clone() * bytecode_full_lookup_op,
            ),
            (
                "bytecode lookup is code".into(),
                bytecode_full_lookup_not_code,
            ),
        ]);
        //inv of operand1hi
        constraints.extend(iszero_gadget_hi.get_constraints());
        //inv of operand1lo
        constraints.extend(iszero_gadget_lo.get_constraints());

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let bytecode_lookup = query_expression(meta, |meta| config.get_bytecode_full_lookup(meta));
        vec![
            ("pop_lookup_stack 0".into(), stack_lookup_0),
            ("pop_lookup_stack 1".into(), stack_lookup_1),
            ("lookup_bytecode_full".into(), bytecode_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);

        let (stack_pop_1, b) = current_state.get_pop_stack_row_value(&trace);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1]);

        let b_hi = F::from_u128((b >> 128).as_u128());
        let b_lo = F::from_u128(b.low_u128());
        let lo_inv = U256::from_little_endian(b_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        let hi_inv = U256::from_little_endian(b_hi.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        //hi_inv
        assign_or_panic!(core_row_1[HI_INV_COLUMN_ID], hi_inv);
        //lo_inv
        assign_or_panic!(core_row_1[LO_INV_COLUMN_ID], lo_inv);

        //hi_inv
        let hi_is_zero = if b_hi == F::ZERO {
            U256::one()
        } else {
            U256::zero()
        };
        assign_or_panic!(core_row_1[HI_ZERO_COLUMN_ID], hi_is_zero);
        //lo_inv
        let lo_is_zero = if b_lo == F::ZERO {
            U256::one()
        } else {
            U256::zero()
        };
        assign_or_panic!(core_row_1[LO_ZERO_COLUMN_ID], lo_is_zero);

        //is_zero
        let is_zero = hi_is_zero * lo_is_zero;
        assign_or_panic!(core_row_1[HI_LO_ZERO_COLUMN_ID], is_zero);

        let mut code_addr = core_row_1.code_addr;

        let mut next_op = OpcodeId::JUMPDEST;
        //dest pc
        let pc = if is_zero.is_zero() {
            a.as_u64()
        } else {
            //b is 0
            code_addr = U256::from(0);
            next_op = OpcodeId::default();
            0_u64
        };

        core_row_1.insert_bytecode_full_lookup(pc, next_op, code_addr, Some(0.into()));

        let core_row_0 = ExecutionState::JUMPI.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(JumpiGadget {
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
        let stack = Stack::from_slice(&[1.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::JUMPI, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[19] = Some(stack_pointer.into());
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
    fn assign_and_constraint_condzero() {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::JUMPI, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[19] = Some(stack_pointer.into());
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
