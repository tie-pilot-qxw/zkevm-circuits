use crate::arithmetic_circuit::operation;

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
const SUB_TAG_COL_IDX: usize = 30;
const SLT_SGT_TAG_COL_IDX: usize = 31;

/// +---+-------+-------+-------+-----------------------+
/// |cnt| 8 col | 8 col | 8 col | 8col                  |
/// +---+-------+-------+-------+-----------------------+
/// | 2 | ARITH(9) |                                    |
/// | 1 | STATE0| STATE1| STATE2| ARITH_TAG_SELECTOR(2) |
/// | 0 | DYNA_SELECTOR   | AUX                         |
/// +---+-------+-------+-------+-----------------------+
pub struct LtGtSltSgtGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for LtGtSltSgtGadget<F>
{
    fn name(&self) -> &'static str {
        "LT_GT_SLT_SGT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::LT_GT_SLT_SGT
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
        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // LT, GT, SLT, SGT gas cost is FASTEST,
            // Only one of the representatives is used here
            gas_left: ExpressionOutcome::Delta(-OpcodeId::LT.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));
        let mut stack_operands = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                if i == 0 { 0 } else { -1 }.expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.extend([value_hi, value_lo]);
        }
        let (arithmetic_tag, arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));

        // constrain arithmetic_operands
        //  if opcode is GT or SGT, then opcode_not_gt_sgt is 0，if opcode is neither GT nor SGT, then opcode_not_gt_sgt is not 0.
        //  if opcode is LT or SLT, then opcode_not_lt_slt is 0，if opcode is neither LT nor SLT, then opcode_not_lt_slt is not 0.
        //  because the Opcode has been constrained, the Opcode can only be one of LT, GT, SLT, and SGT, therefore, when
        // opcode_not_gt_sgt is not 0, the Opcode is LT or SLT.
        // similarly, when opcode_not_lt_slt is not 0, the Opcode is GT or SGT.
        let opcode_not_gt_sgt = (opcode.clone() - OpcodeId::GT.as_u8().expr())
            * (opcode.clone() - OpcodeId::SGT.as_u8().expr());
        let opcode_not_lt_slt = (opcode.clone() - OpcodeId::LT.as_u8().expr())
            * (opcode.clone() - OpcodeId::SLT.as_u8().expr());

        // Lt or Slt
        // stack top 0 is a
        // stack top 1 is b
        // arithmetic_operands[0] = stack top 0 hi  (a hi)
        // arithmetic_operands[1] = stack top 0 lo  (a lo)
        // arithmetic_operands[2] = stack top 1 hi  (b hi)
        // arithmetic_operands[3] = stack top 1 lo  (b lo)
        constraints.extend((0..4).map(|i| {
            (
                format!("operand[{}] in arithmetic = in state lookup", i),
                opcode_not_gt_sgt.clone()
                    * (stack_operands[i].clone() - arithmetic_operands[i].clone()),
            )
        }));

        // Gt or Sgt
        // stack top 0 is a
        // stack top 1 is b
        // arithmetic_operands[0] = stack top 1 hi  (b hi)
        // arithmetic_operands[1] = stack top 1 lo  (b lo)
        // arithmetic_operands[2] = stack top 0 hi  (a, hi)
        // arithmetic_operands[3] = stack top 0 lo  (a, lo)
        constraints.extend((0..4).map(|i| {
            let f_i = (i + 2) % 4;
            (
                format!(
                    "operand[{}] in state lookup = operand[{}] in arithmetic",
                    i, f_i
                ),
                opcode_not_lt_slt.clone()
                    * (stack_operands[i].clone() - arithmetic_operands[f_i].clone()),
            )
        }));

        // lt/slt and sgt/gt
        // arithmetic_operands[4]
        // arithmetic_operands[5]
        // arithmetic_operands[6] = stack push hi
        // arithmetic_operands[7] = stack push lo
        constraints.extend([
            (
                "result hi in state push = 0".into(),
                stack_operands[4].clone(),
            ),
            (
                "arithemetic operand[6] carry_hi = stack push lo".into(),
                arithmetic_operands[6].clone() - stack_operands[5].clone(),
            ),
        ]);

        // construct the selector and constrain it
        // if arithmetic_tag is Sub, then vers[30] is 1 and vers[31] is 0
        // if arithmetic_tag is SltSgt, then vers[31] is 1 and vers[30] is 0
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[SUB_TAG_COL_IDX], Rotation::prev()),
            meta.query_advice(config.vers[SLT_SGT_TAG_COL_IDX], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());

        // make sure the arithmetic tag must be Sub or SltSgt
        // if vers[30] is 1, then selector is 1*(arithmetic_tag - arithmetic::Tag::Sub)
        // if vers[31] is 1, then selector is 1*(arithmetic_tag - arithmetic::Tag::SltSgt)
        constraints.extend([(
            "arithmetic tag is correct".into(),
            selector.select(&[
                arithmetic_tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
                arithmetic_tag.clone() - (arithmetic::Tag::SltSgt as u8).expr(),
            ]),
        )]);

        // make sure the opcode must be one of LT, GT, SLT, or SGT
        constraints.push((
            "opcode is correct".into(),
            selector.select(&[
                // constraint is executed when vers[30] is 1
                (opcode.clone() - OpcodeId::LT.as_u8().expr())
                    * (opcode.clone() - OpcodeId::GT.as_u8().expr()),
                // constraint is executed when vers[31] is 1
                (opcode.clone() - OpcodeId::SLT.as_u8().expr())
                    * (opcode.clone() - OpcodeId::SGT.as_u8().expr()),
            ]),
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
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // pop two elements from the top of the stack
        let (stack_pop_a, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_b, b) = current_state.get_pop_stack_row_value(&trace);

        // get arithmetic_tag and arithmetic_rows
        let (is_lt_gt, (arithmetic, result)) = match trace.op {
            OpcodeId::LT => (true, operation::sub::gen_witness(vec![a, b])),
            OpcodeId::GT => (true, operation::sub::gen_witness(vec![b, a])),
            OpcodeId::SLT => (false, operation::slt_sgt::gen_witness(vec![a, b])),
            OpcodeId::SGT => (false, operation::slt_sgt::gen_witness(vec![b, a])),
            _ => panic!("not Lt or Gt or Slt or Sgt"),
        };

        // get carry hi, which is at 128-th bit
        let stack_result = result[1] >> 128;
        assert_eq!(stack_result, current_state.stack_top.unwrap());

        let stack_push = current_state.get_push_stack_row(trace, stack_result);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_push]);

        // if tag is sub, then vers_30 is 1 and vers_31 is 0
        // if tag is SltSgt, then vers_31 is 1 and vers_30 is 0
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [SUB_TAG_COL_IDX, SLT_SGT_TAG_COL_IDX],
            !is_lt_gt as usize,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::LT_GT_SLT_SGT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_a, stack_pop_b, stack_push],
            arithmetic,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(LtGtSltSgtGadget {
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
                Some(gas_left_before_exec.into());
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
        prover.assert_satisfied();
    }

    #[test]
    fn test_lt_normal() {
        // b, a
        let stack = Stack::from_slice(&[3.into(), 2.into()]);
        run(OpcodeId::LT, stack, U256::one());

        let stack = Stack::from_slice(&[3.into(), 3.into()]);
        run(OpcodeId::LT, stack, U256::zero());

        let stack = Stack::from_slice(&[3.into(), 4.into()]);
        run(OpcodeId::LT, stack, U256::zero());
    }

    #[test]
    fn test_gt_normal() {
        // b, a
        let stack = Stack::from_slice(&[2.into(), 3.into()]);
        run(OpcodeId::GT, stack, U256::one());

        let stack = Stack::from_slice(&[3.into(), 3.into()]);
        run(OpcodeId::GT, stack, U256::zero());

        let stack = Stack::from_slice(&[4.into(), 3.into()]);
        run(OpcodeId::GT, stack, U256::zero());
    }

    #[test]
    fn test_slt_normal() {
        // b, a
        let stack = Stack::from_slice(&[3.into(), 2.into()]);
        run(OpcodeId::SLT, stack, U256::one());

        let stack = Stack::from_slice(&[3.into(), 3.into()]);
        run(OpcodeId::SLT, stack, U256::zero());

        let stack = Stack::from_slice(&[3.into(), 4.into()]);
        run(OpcodeId::SLT, stack, U256::zero());
    }

    #[test]
    fn test_sgt_normal() {
        // b, a
        let stack = Stack::from_slice(&[2.into(), 3.into()]);
        run(OpcodeId::SGT, stack, U256::one());

        let stack = Stack::from_slice(&[3.into(), 3.into()]);
        run(OpcodeId::SGT, stack, U256::zero());

        let stack = Stack::from_slice(&[4.into(), 3.into()]);
        run(OpcodeId::SGT, stack, U256::zero());
    }
}
