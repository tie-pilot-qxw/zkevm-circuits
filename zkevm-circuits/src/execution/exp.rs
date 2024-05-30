use crate::arithmetic_circuit::operation;
use crate::constant::NUM_VERS;
use crate::execution::storage::get_multi_inverse;
use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::{assign_or_panic, bitwise, exp};
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;

/// +---+---------+------------------------------------------------------------------+--------+---------+
/// |cnt| 8 col   |                      8 col                                       | 8 col  |  8col   |
/// +---+---------+------------------------------------------------------------------+--------+---------+
/// | 2 |  U64Overflow | most_significant_byte_len_hi | most_significant_byte_len_lo |     INDEX_HI_INV |
/// | 1 | STATE0  |                    STATE1                                        | STATE2 | EXP     |
/// | 0 |                            DYNA_SELECTOR                                   | AUX              |
/// +---+---------+----------------+--------+----------------------------------------+------------------+
pub struct ExpGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ExpGadget<F>
{
    fn name(&self) -> &'static str {
        "EXP"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::EXP
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 0)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
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

        // calc gas
        let mut index_arr = vec![];
        for i in 0..2 {
            let entry = config.get_most_significant_byte_len_lookup(meta, i);
            let (acc_2, index) = extract_lookup_expression!(most_significant_byte_len, entry);
            let suffix = if i == 0 { "hi" } else { "lo" };
            constraints.push((
                format!("acc_2_{} == exponent_{}", suffix, suffix),
                acc_2 - stack_operands[1][i].clone(),
            ));
            index_arr.push(index);
        }
        let index_hi_inv = meta.query_advice(config.vers[NUM_VERS - 1], Rotation(-2));
        let is_zero = SimpleIsZero::new(
            &index_arr[0].clone(),
            &index_hi_inv,
            "most_significant_byte_len_hi".into(),
        );
        constraints.extend(is_zero.get_constraints());
        let most_significant_byte_len = select::expr(
            is_zero.expr(),
            index_arr[1].clone(),
            index_arr[0].clone() + 16.expr(),
        );
        let gas_cost = most_significant_byte_len * (GasCost::EXP_BYTE_TIMES as u8).expr()
            + OpcodeId::EXP.constant_gas_cost().expr();

        // gas_left not overflow
        let current_gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left_u64_overflow".into());
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            ("gas_left_hi == 0".into(), gas_left_hi.clone()),
            (
                "gas_left_lo = current_gas_left".into(),
                gas_left_lo - current_gas_left.clone(),
            ),
            (
                "gas_left not overflow".into(),
                1.expr() - gas_left_not_overflow.expr(),
            ),
        ]);

        // other constraints
        let entry = config.get_exp_lookup(meta);
        let (base, index, power) = extract_lookup_expression!(exp, entry);

        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        constraints.extend([
            (
                "base_hi = stack_top0_hi(stack base_hi)".into(),
                stack_operands[0][0].clone() - base[0].clone(),
            ),
            (
                "base_lo = stack_top0_lo(stack base_lo)".into(),
                stack_operands[0][1].clone() - base[1].clone(),
            ),
            (
                "index_hi = stack_top1_hi(stack index_hi)".into(),
                stack_operands[1][0].clone() - index[0].clone(),
            ),
            (
                "index_lo = stack_top1_lo(stack index_lo)".into(),
                stack_operands[1][1].clone() - index[1].clone(),
            ),
            (
                "power_hi = stack_top2_hi(stack power_hi)".into(),
                stack_operands[2][0].clone() - power[0].clone(),
            ),
            (
                "power_lo = stack_top2_lo(stack power_lo)".into(),
                stack_operands[2][1].clone() - power[1].clone(),
            ),
            ("opcode".into(), opcode - OpcodeId::EXP.as_u8().expr()),
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
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        let most_significant_byte_len_hi = query_expression(meta, |meta| {
            config.get_most_significant_byte_len_lookup(meta, 0)
        });
        let most_significant_byte_len_lo = query_expression(meta, |meta| {
            config.get_most_significant_byte_len_lookup(meta, 1)
        });
        let arithmetic_tiny_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("exp lookup".into(), exp_lookup),
            (
                "most_significant_byte_len_hi".into(),
                most_significant_byte_len_hi,
            ),
            (
                "most_significant_byte_len_lo".into(),
                most_significant_byte_len_lo,
            ),
            ("arithmetic tiny".into(), arithmetic_tiny_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_base_row, base) = current_state.get_pop_stack_row_value(&trace);
        let (stack_index_row, index) = current_state.get_pop_stack_row_value(&trace);

        let expect_power = current_state.stack_top.unwrap_or_default();

        let exponent_hi = (index >> 128).as_u128();
        let exponent_lo = index.low_u128();

        let most_significant_byte_len_hi =
            bitwise::Row::from_operation::<F>(bitwise::Tag::Or, exponent_hi, 0u128);
        let most_significant_byte_len_lo =
            bitwise::Row::from_operation::<F>(bitwise::Tag::Or, exponent_lo, 0u128);
        let index_hi_inv =
            get_multi_inverse::<F>(most_significant_byte_len_hi.last().unwrap().index);

        let (u64_overflow_rows, _) =
            operation::u64overflow::gen_witness::<F>(vec![current_state.gas_left.into()]);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_arithmetic_tiny_lookup(0, &u64_overflow_rows);
        core_row_2.insert_most_significant_byte_len_lookups(
            0,
            &most_significant_byte_len_hi.last().unwrap(),
        );
        core_row_2.insert_most_significant_byte_len_lookups(
            1,
            &most_significant_byte_len_lo.last().unwrap(),
        );
        assign_or_panic!(core_row_2[NUM_VERS - 1], index_hi_inv);

        // get exp rows
        let (actual_calc_power, exp_rows, arithmetic_mul_rows) =
            exp::Row::from_operands(base, index);
        assert_eq!(actual_calc_power, expect_power);

        // generate stack push row
        let stack_push_0 = current_state.get_push_stack_row(trace, expect_power);

        // generate core row
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_base_row, &stack_index_row, &stack_push_0]);
        core_row_1.insert_exp_lookup(base, index, actual_calc_power); // it will check a ** b = c

        let core_row_0 = ExecutionState::EXP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(arithmetic_mul_rows);
        arithmetic_rows.extend(u64_overflow_rows);

        let mut bitwise_rows = vec![];
        bitwise_rows.extend(most_significant_byte_len_hi);
        bitwise_rows.extend(most_significant_byte_len_lo);

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_base_row, stack_index_row, stack_push_0],
            arithmetic: arithmetic_rows,
            exp: exp_rows,
            bitwise: bitwise_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ExpGadget {
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
    fn run(base: U256, index: U256) {
        let stack = Stack::from_slice(&[index, base]);
        let (expect_pow, _) = base.overflowing_pow(index);
        let byte_len = ((index.bits() + 7) / 8) as u64;
        let gas_cost = byte_len * GasCost::EXP_BYTE_TIMES + OpcodeId::EXP.constant_gas_cost();
        println!(
            "base:{:?}, index:{:?}, expect_pow:{:?}",
            base, index, expect_pow
        );
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(expect_pow),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + gas_cost;
        let mut trace = prepare_trace_step!(0, OpcodeId::EXP, stack);
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
    fn test_exp1() {
        // calc 2^10
        run(U256::from(2), U256::from(10))
    }

    #[test]
    fn test_exp2() {
        // calc 2^128
        run(U256::from(2), U256::from(128))
    }

    #[test]
    fn test_exp3() {
        // calc 2^255
        run(U256::from(2), U256::from(255))
    }

    #[test]
    fn test_exp4() {
        // calc 2^257
        run(U256::from(2), U256::from(257))
    }

    #[test]
    fn test_exp5() {
        // calc 2^0
        run(U256::from(2), U256::zero())
    }
}
