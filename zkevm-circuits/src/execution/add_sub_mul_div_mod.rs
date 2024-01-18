use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
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

/// +---+-------+-------+-------+-----------------------+
/// |cnt| 8 col | 8 col | 8 col | 8col                  |
/// +---+-------+-------+-------+-----------------------+
/// | 2 | ARITH(9) |                                    |
/// | 1 | STATE0| STATE1| STATE2| ARITH_TAG_SEL(4)      |
/// | 0 | DYNA_SELECTOR   | AUX                         |
/// +---+-------+-------+-------+-----------------------+
pub struct AddSubMulDivModGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for AddSubMulDivModGadget<F>
{
    fn name(&self) -> &'static str {
        "ADD_SUB_MUL_DIV_MOD"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ADD_SUB_MUL_DIV_MOD
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
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
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

        // construct the selector and constrain it
        // if opcode is ADD, then vers[27] is 1 and vers[28]、vers[29]、vers[30]、vers[31] is 0
        // if opcode is SUB, then vers[28] is 1 and vers[27]、vers[29]、vers[30]、vers[31] is 0
        // if opcode is MUL, then vers[29] is 1 and vers[27]、vers[28]、vers[30]、vers[31] is 0
        // if opcode is DIV, then vers[30] is 1 and vers[27]、vers[28]、vers[29]、vers[31] is 0
        // if opcode is MOD, then vers[31] is 1 and vers[27]、vers[28]、vers[29]、vers[30] is 0
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[27], Rotation::prev()),
            meta.query_advice(config.vers[28], Rotation::prev()),
            meta.query_advice(config.vers[29], Rotation::prev()),
            meta.query_advice(config.vers[30], Rotation::prev()),
            meta.query_advice(config.vers[31], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());

        // make sure the Opcode must be one of ADD, SUB, MUL, DIV or MOD
        // if vers[27] is 1, then selector is 1*(opcode.clone() - OpcodeId::ADD)
        // if vers[28] is 1, then selector is 1*(opcode.clone() - OpcodeId::SUB)
        // if vers[29] is 1, then selector is 1*(opcode.clone() - OpcodeId::MUL)
        // if vers[30] is 1, then selector is 1*(opcode.clone() - OpcodeId::DIV)
        // if vers[31] is 1, then selector is 1*(opcode.clone() - OpcodeId::MOD)
        constraints.push((
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::ADD.as_u8().expr(),
                opcode.clone() - OpcodeId::SUB.as_u8().expr(),
                opcode.clone() - OpcodeId::MUL.as_u8().expr(),
                opcode.clone() - OpcodeId::DIV.as_u8().expr(),
                opcode.clone() - OpcodeId::MOD.as_u8().expr(),
            ]),
        ));

        // constrain arithmetic tag and arithmetic operands
        let (tag, arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));

        // constrain arithmetic tag
        // make sure the arithmetic tag must be one of Add, Sub, Mul, or DivMod
        constraints.extend([(
            "arithmetic tag is correct".into(),
            selector.select(&[
                // constraint is executed when vers[27] is 1
                tag.clone() - (arithmetic::Tag::Add as u8).expr(),
                // constraint is executed when vers[28] is 1
                tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
                // constraint is executed when vers[29] is 1
                tag.clone() - (arithmetic::Tag::Mul as u8).expr(),
                // constraint is executed when vers[30] is 1
                tag.clone() - (arithmetic::Tag::DivMod as u8).expr(),
                // constraint is executed when vers[31] is 1
                tag.clone() - (arithmetic::Tag::DivMod as u8).expr(),
            ]),
        )]);

        // constrain arithmetic operands
        // stack top 0 hi = arithmetic_operands[0]
        // stack top 0 lo = arithmetic_operands[1]
        // stack top 1 hi = arithmetic_operands[2]
        // stack top 1 lo = arithmetic_operands[3]
        // opcode is add or sub or mul or div:
        //    stack push val hi = arithmetic_operands[4] result_hi(sum、difference、product、quotient)
        //    stack push val lo = arithmetic_operands[5] result_lo(sum、difference、product、quotient)
        // opcode is mod
        //   stack push val hi = arithmetic_operands[6] remainder_hi
        //   stack push val lo = arithmetic_operands[7] remainder_lo
        constraints.extend((0..4).map(|i| {
            (
                format!("stack operand[{}] in arithmetic = in state lookup", i),
                stack_operands[i].clone() - arithmetic_operands[i].clone(),
            )
        }));

        // if opcode is ADD, then selector is 1*arithmetic_operands[4]
        // if opcode is SUB, then selector is 1*arithmetic_operands[4]
        // if opcode is MUL, then selector is 1*arithmetic_operands[4]
        // if opcode is DIV, then selector is 1*arithmetic_operands[4]
        // if opcode is MOD, then selector is 1*arithmetic_operands[6]
        constraints.push((
            "arithmetic result hi".into(),
            stack_operands[4].clone()
                - selector.select(&[
                    arithmetic_operands[4].clone(),
                    arithmetic_operands[4].clone(),
                    arithmetic_operands[4].clone(),
                    arithmetic_operands[4].clone(),
                    arithmetic_operands[6].clone(),
                ]),
        ));

        // if opcode is ADD, then selector is 1*arithmetic_operands[5]
        // if opcode is SUB, then selector is 1*arithmetic_operands[5]
        // if opcode is MUL, then selector is 1*arithmetic_operands[5]
        // if opcode is DIV, then selector is 1*arithmetic_operands[5]
        // if opcode is MOD, then selector is 1*arithmetic_operands[7]
        constraints.push((
            "arithmetic result lo".into(),
            stack_operands[5].clone()
                - selector.select(&[
                    arithmetic_operands[5].clone(),
                    arithmetic_operands[5].clone(),
                    arithmetic_operands[5].clone(),
                    arithmetic_operands[5].clone(),
                    arithmetic_operands[7].clone(),
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
        // get two elements from the top of the stack
        let (stack_pop_a, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_b, b) = current_state.get_pop_stack_row_value(&trace);

        // get arithmetic_tag and arithmetic_rows
        let (tag_selector_index, (arithmetic_rows, result)) = match trace.op {
            OpcodeId::ADD => (0, operation::add::gen_witness(vec![a, b])),
            OpcodeId::SUB => (1, operation::sub::gen_witness(vec![a, b])),
            OpcodeId::MUL => (2, operation::mul::gen_witness(vec![a, b])),
            OpcodeId::DIV => (3, operation::div_mod::gen_witness(vec![a, b])),
            OpcodeId::MOD => (4, operation::div_mod::gen_witness(vec![a, b])),
            _ => panic!("not Add or Sub or Mul"),
        };

        // get stack push row
        let stack_push = if trace.op == OpcodeId::DIV {
            assert_eq!(result[1], current_state.stack_top.unwrap());
            current_state.get_push_stack_row(trace, result[1])
        } else {
            assert_eq!(result[0], current_state.stack_top.unwrap());
            current_state.get_push_stack_row(trace, result[0])
        };

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic_rows);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_push]);

        // tag selector
        simple_selector_assign(
            [
                &mut core_row_1.vers_27,
                &mut core_row_1.vers_28,
                &mut core_row_1.vers_29,
                &mut core_row_1.vers_30,
                &mut core_row_1.vers_31,
            ],
            tag_selector_index as usize,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::ADD_SUB_MUL_DIV_MOD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_b, stack_pop_a, stack_push],
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(AddSubMulDivModGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(opcode: OpcodeId, stack: Stack, stack_top: U256) {
        // prepare a state to generate witness
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, opcode, stack);
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

    #[test]
    fn test_add_normal() {
        // b, a
        let stack = Stack::from_slice(&[2.into(), 1.into()]);
        run(OpcodeId::ADD, stack, U256::from(3))
    }

    #[test]
    fn test_add_max() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, 1.into()]);
        run(OpcodeId::ADD, stack, U256::zero())
    }

    #[test]
    fn test_mul_normal() {
        // b, a
        let stack = Stack::from_slice(&[2.into(), 2.into()]);
        println!("{:?},{:?}", OpcodeId::MUL.as_u8(), OpcodeId::ADD.as_u8());
        run(OpcodeId::MUL, stack, U256::from(4))
    }

    #[test]
    fn test_mul_max() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, 1.into()]);
        run(OpcodeId::MUL, stack, U256::MAX);
    }

    #[test]
    fn test_mul_max2() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, 2.into()]);
        run(OpcodeId::MUL, stack, U256::MAX - 1);
    }

    #[test]
    fn test_sub_normal() {
        let stack = Stack::from_slice(&[2.into(), 3.into()]);
        run(OpcodeId::SUB, stack, U256::one());

        // b, a
        let stack = Stack::from_slice(&[2.into(), 2.into()]);
        run(OpcodeId::SUB, stack, U256::zero());
    }

    #[test]
    fn test_sub_max() {
        // b, a
        let stack = Stack::from_slice(&[1.into(), U256::MAX]);
        run(OpcodeId::SUB, stack, U256::MAX - 1);
    }

    #[test]
    fn test_sub_max2() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, U256::MAX]);
        run(OpcodeId::SUB, stack, U256::zero());
    }

    #[test]
    fn test_div_normal() {
        let stack = Stack::from_slice(&[2.into(), 4.into()]);
        run(OpcodeId::DIV, stack, U256::from(2));

        let stack = Stack::from_slice(&[2.into(), 3.into()]);
        run(OpcodeId::DIV, stack, U256::from(1));
    }

    #[test]
    fn test_div_max() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, 1.into()]);
        run(OpcodeId::DIV, stack, U256::zero());
    }

    #[test]
    fn test_div_zero() {
        // b, a
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        run(OpcodeId::DIV, stack, U256::zero());
    }

    #[test]
    fn test_mod_normal() {
        let stack = Stack::from_slice(&[2.into(), 4.into()]);
        run(OpcodeId::MOD, stack, U256::zero());

        let stack = Stack::from_slice(&[2.into(), 3.into()]);
        run(OpcodeId::MOD, stack, U256::one());
    }

    #[test]
    fn test_mod_max() {
        // b, a
        let stack = Stack::from_slice(&[U256::MAX, 1.into()]);
        run(OpcodeId::MOD, stack, U256::one());
    }

    // #[test]
    // fn test_mod_zero() {
    //     // b, a
    //     let stack = Stack::from_slice(&[0.into(), 1.into()]);
    //     run(OpcodeId::MOD, stack, U256::zero());
    // }
}
