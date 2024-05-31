use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, get_and_insert_shl_shr_rows, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
const SHIFT_MAX: u8 = 255;

/// Algorithm overview:
///     1.pop two elements from the top of the stack
///        stack top0 is shift
///        stack top1 is value
///     2. if opcode is SHL, then calc value << shift
///        if opcode is SHR, then calc value >> shift
/// note: the calculation here is not a direct displacement operation, but a multiplication or division operation, the steps are as follows:
/// SHL:
///     1. get shift、value from stack
///     2. 255-shift
///     3. calc mul_num: 2 << shift
///     3. value * mul_num --> value * (2 << shift)
/// SHR:
///     1. get shift、value from stack
///     2. 255-shift
///     3. calc div_num: 2 << shift
///     3. value / div_num --> value / (2 << shift)
///  255-shift operation Arithmetic(Sub) subcircuit for constraints, the main purpose is to determine whether shift is greater than or equal to 256, that is, whether 2<<shift will overflow.
///  2 << shift operation uses Exp subcircuit for constraints
///  value * mul_num(or value / div_num) uses Algorithm(Mul Or Div) subcircuit for constraints
///
/// Table layout:
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH0 | ARITH1|                 |
/// | 1 | STATE0| STATE1| STATE2|     EXP  |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
/// ARITH0 Arithmetic(Sub) lookup, 9 columns
/// ARITH1 Arithmetic-Mul(SHL) or Arithmetic-Div(SHR) lookup, 9 columns
/// STATE0: operand_0 lookup, 8 columns
/// STATE1: operand_1 lookup, 8 columns
/// STATE2: final_result lookup, 8 columns
/// EXP: exp lookup, 6 columns
pub struct ShlShrGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ShlShrGadget<F>
{
    fn name(&self) -> &'static str {
        "SHL_SHR"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SHL_SHR
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
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // SHL, SHR gas cost is FASTEST,
            // Only one of the representatives is used here
            gas_left: ExpressionOutcome::Delta(-OpcodeId::SHL.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
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
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));

        // stack constraints
        let mut stack_operands = vec![];
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
            stack_operands.push([value_hi, value_lo]);
        }

        let (sub_tag, sub_arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));
        let (mul_div_tag, mul_div_arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 1));

        // sub arithmetic constraints
        constraints.extend(config.get_shl_shr_sar1_sub_arith_constraints(
            &stack_operands[0],
            &mul_div_arithmetic_operands,
            &sub_arithmetic_operands,
        ));

        // mul_div_arithmetic constraints
        constraints.extend(config.get_shl_shr_sar1_mul_div_arith_constraints(
            &stack_operands[1],
            &stack_operands[2],
            &mul_div_arithmetic_operands,
        ));

        // exp constraints
        constraints.extend(config.get_shl_shr_sar1_exp_constraints(
            meta,
            &stack_operands[0],
            &mul_div_arithmetic_operands,
        ));

        // constrain Opcode
        // OpcodeId::Shr - OpcodeId::Shl = 1
        // arithmetic::Tag::DivMod - arithmetic::Tag::Mul = 1
        // if opcode is SHL, then opcode_is_shl is 1 and opcode_is_shr is 0
        // if opcode is SHR, then opcode_is_shl is 0 and opcode_is_shr is 1
        // if arithmetic tag is Mul, then arithmetic_tag_is_mul is 1 and arithmetic_tag_is_div is 0
        // if arithmetic tag is DivMod, then arithmetic_tag_is_mul is 0 and arithmetic_tag_is_div is 1
        // note: if opcode is SHL, then arithmetic_tag must be Mul
        //       if opcode is SHR, then arithmetic_tag must be DivMod
        let opcode_is_shl = OpcodeId::SHR.as_u8().expr() - opcode.clone();
        let opcode_is_shr = opcode.clone() - OpcodeId::SHL.as_u8().expr();
        let arithmetic_tag_is_mul = (arithmetic::Tag::DivMod as u8).expr() - mul_div_tag.clone();
        let arithmetic_tag_is_div = mul_div_tag - (arithmetic::Tag::Mul as u8).expr();
        constraints.extend([
            (
                "opcode must be shl or shr".into(),
                opcode_is_shl.clone() * opcode_is_shr.clone(),
            ),
            (
                "opcode is shl ==> mul_div_arithmetic tag is mul".into(),
                opcode_is_shl * (1.expr() - arithmetic_tag_is_mul),
            ),
            (
                "opcode is shr ==> mul_div_arithmetic tag is div".into(),
                opcode_is_shr * (1.expr() - arithmetic_tag_is_div),
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
        // mul_div arithmetic lookup
        let mul_div_arithmetic =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 1));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("exp lookup".into(), exp_lookup),
            ("arithmetic sub lookup".into(), sub_arithmetic),
            ("arithmetic mul_div lookup".into(), mul_div_arithmetic),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // pop two elements from the top of the stack: shift, value
        let (stack_pop_0, stack_shift) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, stack_value) = current_state.get_pop_stack_row_value(&trace);

        // get stack push value (shl calc result)
        let stack_value_shift_result = current_state.stack_top.unwrap_or_default();

        assert_eq!(
            if stack_shift > SHIFT_MAX.into() {
                0.into()
            } else {
                match trace.op {
                    OpcodeId::SHL => stack_value << stack_shift,
                    OpcodeId::SHR => stack_value >> stack_shift,
                    _ => panic!("not shl or shr"),
                }
            },
            stack_value_shift_result
        );

        // get stack push row
        let stack_push_0 = current_state.get_push_stack_row(trace, stack_value_shift_result);

        // construct core_row_2,core_row_1,core_row_0  object
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        let core_row_0 = ExecutionState::SHL_SHR.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // insert state lookup, operand_0,operand_1,final_result
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);

        // get and insert shl or shr rows
        let (arithmetic_rows, exp_rows) = get_and_insert_shl_shr_rows::<F>(
            stack_shift,
            stack_value,
            trace.op,
            &mut core_row_1,
            &mut core_row_2,
        );

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
    Box::new(ShlShrGadget {
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
        let gas_left_before_exec = current_state.gas_left + OpcodeId::SHL.constant_gas_cost();
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
        prover.assert_satisfied_par();
    }
    #[test]
    fn test_shl_normal() {
        // shl num normal, index normal
        let stack = Stack::from_slice(&[2.into(), 1.into()]);
        run(OpcodeId::SHL, stack, U256::from(4))
    }

    #[test]
    fn test_shl_shift_max() {
        // shl  num max , index max
        let stack = Stack::from_slice(&[2.into(), 256.into()]);
        run(OpcodeId::SHL, stack, U256::zero())
    }

    #[test]
    fn test_shl_value_max() {
        // shl  num max , index max
        // one bit is reduced, and the last bit is filled with 0，which is equivalent to the last bit changing from
        // 1 to 0, which is equivalent to subtracting 1
        let stack = Stack::from_slice(&[U256::MAX, 1.into()]);
        run(OpcodeId::SHL, stack, U256::MAX - 1)
    }

    #[test]
    fn test_shl_mul_overflow() {
        // shl num normal, index max
        // shift: 255
        // value: 2
        // mul_num: 2 << shift ---> 2 << 255
        // shl result: value * mul_num ---> 2 * (2<<255)
        let stack = Stack::from_slice(&[2.into(), 255.into()]);
        run(OpcodeId::SHL, stack, U256::zero())
    }

    #[test]
    fn test_shl_max_overflow() {
        // shl index overflow
        let stack = Stack::from_slice(&[U256::MAX, 256.into()]);
        run(OpcodeId::SHL, stack, U256::zero())
    }

    #[test]
    fn test_shr_normal() {
        // shr num normal,index normal
        let stack = Stack::from_slice(&[2.into(), 1.into()]);
        run(OpcodeId::SHR, stack, U256::from(1))
    }

    #[test]
    fn test_shr_normal_max() {
        // shr num normal, index max
        let stack = Stack::from_slice(&[0xFF.into(), 255.into()]);
        run(OpcodeId::SHR, stack, U256::from(0))
    }

    #[test]
    fn test_shr_max() {
        // shr  num max , index max
        let stack = Stack::from_slice(&[U256::MAX, 255.into()]);
        run(OpcodeId::SHR, stack, U256::from(1))
    }

    #[test]
    fn test_shr_max_overflow() {
        // shr index overflow
        let stack = Stack::from_slice(&[U256::MAX, 256.into()]);
        run(OpcodeId::SHR, stack, U256::from(0))
    }
}
