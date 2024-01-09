use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, exp, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
const SHIFT_MAX: u8 = 255;

/// ShrGadget Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// ARITH0 9 cols, record sub  
/// ARITH1 9 cols, record div
/// STATE0: operand_0 lookup , 8 columns
/// STATE1: operand_1 lookup , 8 columns
/// STATE2: final_result lookup, 8 columns
/// EXP: exp lookup , 6 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH0 | ARITH1|                 |
/// | 1 | STATE0| STATE1| STATE2|     EXP  |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
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
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        let mut stack_operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        // stack constraints
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
            stack_operands.extend([value_hi, value_lo]);
        }
        let (sub_tag, sub_arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));
        let (div_tag, div_arithmetic_operands_full) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 1));
        let entry = config.get_exp_lookup(meta);
        let (base, index, power) = extract_lookup_expression!(exp, entry);
        // sub arithmetic constraints
        // sub_arithmetic_operands_full[0] is 0
        // sub_arithmetic_operands_full[1] is 255
        // sub_arithmetic_operands_full[2] is stack_operands[0](stack top 1 hi)
        // sub_arithmetic_operands_full[3] is stack_operands[1](stack top 1 lo)
        // if carry = 1 , div_num = 0;
        // if carry = 1 , div_arithmetic_operands_full[4] = 0; (quotient hi = 0)
        //      div_arithmetic_operands_full[5] = 0;(quotient lo = 0)
        constraints.extend([
            (
                "sub_arithmetic operand 0 hi = 0".into(),
                sub_arithmetic_operands_full[0].clone(),
            ),
            (
                "sub_arithmetic operand 0 lo = 255".into(),
                sub_arithmetic_operands_full[1].clone() - 255.expr(),
            ),
            (
                "sub_arithmetic operand 1 hi = stack_operands[0]".into(),
                sub_arithmetic_operands_full[2].clone() - stack_operands[0].clone(),
            ),
            (
                "sub_arithmetic operand 1 lo = stack_operands[1]".into(),
                sub_arithmetic_operands_full[3].clone() - stack_operands[1].clone(),
            ),
            (
                "sub_arithmetic carry=1 => div_num_hi = 0".into(),
                sub_arithmetic_operands_full[6].clone() * div_arithmetic_operands_full[2].clone(),
            ),
            (
                "sub_arithmetic carry=1 => div_num_lo = 0".into(),
                sub_arithmetic_operands_full[6].clone() * div_arithmetic_operands_full[3].clone(),
            ),
            (
                "sub_arithmetic carry=1 => quotient_hi = 0".into(),
                sub_arithmetic_operands_full[6].clone() * div_arithmetic_operands_full[4].clone(),
            ),
            (
                "sub_arithmetic carry=1 => quotient_lo = 0".into(),
                sub_arithmetic_operands_full[6].clone() * div_arithmetic_operands_full[5].clone(),
            ),
        ]);
        // div arithmetic constraints
        // stack_operands[2] (stack top 2 hi)=  div_arithmetic_operands_full[0]
        // stack_operands[3] (stack top 2 lo)=  div_arithmetic_operands_full[1]
        // quotient , final result:
        //      stack_operands[4] (stack top 3 hi) = div_arithmetic_operands_full[4]
        //      stack_operands[5] (stack top 3 lo) = div_arithmetic_operands_full[5]
        constraints.extend([
            (
                "div_arithmetic operand 0 hi = stack operands[2]".into(),
                stack_operands[2].clone() - div_arithmetic_operands_full[0].clone(),
            ),
            (
                "div_arithmetic operand 0 lo= stack operands[3]".into(),
                stack_operands[3].clone() - div_arithmetic_operands_full[1].clone(),
            ),
            (
                "div_arithmetic operand 2 hi = stack operands[4]".into(),
                stack_operands[4].clone() - div_arithmetic_operands_full[4].clone(),
            ),
            (
                "div_arithmetic operand 2 lo = stack operands[5]".into(),
                stack_operands[5].clone() - div_arithmetic_operands_full[5].clone(),
            ),
        ]);
        // exp constraints
        // base = 2
        // index_hi/lo = stack_operands[0/1](stack top 1 hi/lo)
        // power_hi/lo = div_hi/lo
        constraints.extend([
            ("base hi".into(), base[0].clone()),
            ("base lo".into(), base[1].clone() - 2.expr()),
            (
                "index hi = stack operands[0]".into(),
                index[0].clone() - stack_operands[0].clone(),
            ),
            (
                "index lo = stack operands[1]".into(),
                index[1].clone() - stack_operands[1].clone(),
            ),
            (
                "power equals div num hi".into(),
                power[0].clone() - div_arithmetic_operands_full[2].clone(),
            ),
            (
                "power equals div num lo".into(),
                power[1].clone() - div_arithmetic_operands_full[3].clone(),
            ),
        ]);
        // arithmetic tag
        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::SHR.as_u8().expr()),
            (
                "div arithmetic tag".into(),
                div_tag - (arithmetic::Tag::DivMod as u8).expr(),
            ),
            (
                "sub arithmetic tag".into(),
                sub_tag - (arithmetic::Tag::Sub as u8).expr(),
            ),
        ]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // exp lookup
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        // stack lookup
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        // sub arithmetic lookup
        let sub_arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        // div arithmetic lookup
        let div_arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 1));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("exp lookup".into(), exp_lookup),
            ("arithmetic sub lookup".into(), sub_arithmetic),
            ("arithmetic div lookup".into(), div_arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::SHR);
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value(&trace);
        let c = current_state.stack_top.unwrap_or_default();
        assert_eq!(
            if a > SHIFT_MAX.into() {
                0.into()
            } else {
                b >> a
            },
            c
        );
        let stack_push_0 = current_state.get_push_stack_row(trace, c);
        // 255 - a
        let (arithmetic_sub_rows, _) = operation::sub::gen_witness(vec![U256::from(SHIFT_MAX), a]);
        let div_num = if a > SHIFT_MAX.into() {
            0.into()
        } else {
            U256::from(1) << a
        };
        // b / div_num
        let (arithmetic_div_rows, _) = operation::div_mod::gen_witness(vec![b, div_num]);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // insert sub in lookup
        core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
        // insert div in lookup
        core_row_2.insert_arithmetic_lookup(1, &arithmetic_div_rows);
        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(arithmetic_sub_rows);
        arithmetic_rows.extend(arithmetic_div_rows);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert state lookup, operand_0,operand_1,final_result
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(U256::from(2), a, div_num);
        let core_row_0 = ExecutionState::SHR.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let exp_rows = exp::Row::from_operands(U256::from(2), a, div_num);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            exp: exp_rows,
            arithmetic: arithmetic_rows,
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
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[ignore = "remove ignore after arithmetic is finished"]

    fn run(stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SHR, stack);
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
    fn test_normal() {
        // shr num normal,index normal
        let stack = Stack::from_slice(&[2.into(), 1.into()]);
        run(stack, U256::from(1))
    }
    #[test]
    fn test_normal_max() {
        // shr num normal, index max
        let stack = Stack::from_slice(&[0xFF.into(), 255.into()]);
        run(stack, U256::from(0))
    }
    #[test]
    fn test_max() {
        // shr  num max , index max
        let stack = Stack::from_slice(&[U256::MAX, 255.into()]);
        run(stack, U256::from(1))
    }
    #[test]
    fn test_max_overflow() {
        // shr index overflow
        let stack = Stack::from_slice(&[U256::MAX, 256.into()]);
        run(stack, U256::from(0))
    }
}
