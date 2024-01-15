use crate::arithmetic_circuit::operation;
use crate::constant::{self};
use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::bitwise::Tag;
use crate::witness::{arithmetic, assign_or_panic, bitwise, exp, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::ops::Div;
const NUM_ROW: usize = 3;
const STACK_POINTER_DELTA: i32 = -1;
const STATE_STAMP_DELTA: u64 = 3;
const BYTE_MAX_INDEX: u8 = 31;
/// Signextend gadget
/// algorithm:
/// let operand_0 , operand_1 on stack top,top-1;
/// 1. get a :  a = 128 * 256^operand_0
/// 2. get not_is_zero :
///     2.1) let temp_sum = operand_1 & a;
///     2.2) let not_is_zero = sum(temp_sum.as_bytes())/128;
/// 3. get b_lo :
///     if a_lo == 0,then b_lo = 2^128 -1;
///     if a_lo <> 0, then b_lo  = 2*a_lo -1;
/// 4. get b_hi :
///     if a_hi <> 0 , then b_hi = 2*a_hi -1;
///     if a.hi = 0, a_lo = 0, then b_hi = 2^128 -1;
///     if a_hi = 0, a_lo <> 0, then b_hi = 0;
/// 5. get c_lo :
///     if a_lo == 0 , c_lo =0;
///     if a_lo <> 0, c_lo = 2^128 - 2*a_lo
/// 6. get c_hi :
///     if a_hi == 0 , a_lo = 0 ,then c_hi = 0;
///     if a_hi == 0, a_lo <> 0 , then c_hi = 2^128 -1
///     if a_hi <> 0, then c_hi = 2^128 - 2*a_hi
/// 7. get d_hi : d_hi = not_is_zero * c_hi + (1-not_is_zero)*b_hi
/// 8. get d_lo : d_lo = not_is_zero * c_lo + (1-not_is_zero)*b_lo
/// 9. get final_result :
///     9.1 get operator :
///             if not_is_zero = 1, then operator = ||
///             if not_is_zero = 0, then operator = &
///     9.2 get final_result :
///             final_result = operand_1 operator d
///
/// ARITH 9 columns ,    
/// BITWISE lookup 4 * 5 columns,every lookup takes 5 columns;
/// four lookups:
///     BW0: originated at column 10, operand_1 hi & a hi; 5 columns
///     BW1: operand_1 lo & a lo; 5 columns
///     BW2: operand_1 hi operator d hi; 5 columns
///     BW3: operand_1 lo operator d lo; 5 columns
/// A_HI: a_hi  (algorithm step 1) ,1 column
/// A_LO: a_lo  (algorithm step 1) ,1 column
/// D_HI: d_hi (algorithm step 7) ,1 column
/// D_LO: d_lo  (algorithm step 8) ,1 column  
/// NZ: not_is_zero , 1 column
/// STATE0: operand_0 lookup , 8 columns
/// STATE1: operand_1 lookup , 8 columns
/// STATE2: final_result lookup, 8 columns
/// EXP: exp lookup , 6 columns
/// +---+---------+---------+-------------------------------+---------+
/// |cnt| 8 col   | 8 col   | 8 col  |               8 col            |
/// +---+---------+---------+-------------------------------+---------+
/// | 2 | ARITH     |  BW0 |  BW1  |  BW2  |   BW3          |         |
/// | 1 | STATE0  | STATE1  | STATE2 |                         EXP    |
/// | 0 |       DYNA_SELECTOR   | AUX   | A_HI | A_LO |D_HI |D_LO |NZ |                         |
/// +---+---------+---------+-------------------------------+---------+
pub struct SignextendGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for SignextendGadget<F>
{
    fn name(&self) -> &'static str {
        "SIGNEXTEND"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SIGNEXTEND
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
        let (arithmetic_tag, arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));
        // compute skip width in core row 0
        const SKIP_WIDTH: usize =
            constant::NUM_STATE_HI_COL + constant::NUM_STATE_LO_COL + constant::NUM_AUXILIARY;
        // [a_hi,a_lo]
        let query_a = vec![
            meta.query_advice(config.vers[SKIP_WIDTH], Rotation::cur()),
            meta.query_advice(config.vers[SKIP_WIDTH + 1], Rotation::cur()),
        ];
        // [d_hi,d_lo]
        let query_d = vec![
            meta.query_advice(config.vers[SKIP_WIDTH + 2], Rotation::cur()),
            meta.query_advice(config.vers[SKIP_WIDTH + 3], Rotation::cur()),
        ];
        // not_is_zero
        let query_not_is_zero = meta.query_advice(config.vers[SKIP_WIDTH + 4], Rotation::cur());

        let auxiliary_delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // arithmetic tag constraints
        constraints.push((
            "arithmetic tag is sub".into(),
            arithmetic_tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
        ));
        // [operand_0_hi,operand_0_lo,operand_1_hi,operand_1_lo,result_hi,result_lo]
        let mut operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            // stack constraints
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
        // arithmetic_operands[0] is 0
        // arithmetic_operands[1] is 31
        // arithmetic_operands[2] is operand0_hi
        // arithmetic_operands[3] is operand0_lo
        constraints.extend([
            (
                "arithmetic_operands[0] = 0".into(),
                arithmetic_operands[0].clone(),
            ),
            (
                "arithmetic_operands[1] = 31".into(),
                arithmetic_operands[1].clone() - BYTE_MAX_INDEX.expr(),
            ),
            (
                "arithmetic_operands[2] = operands_0_hi".into(),
                arithmetic_operands[2].clone() - operands[0][0].clone(),
            ),
            (
                "arithmetic_operands[3] = operands_0_lo".into(),
                arithmetic_operands[3].clone() - operands[0][1].clone(),
            ),
        ]);
        // exp constraints
        let exp_entry = config.get_exp_lookup(meta);
        let (base, index, pow) = extract_lookup_expression!(exp, exp_entry);
        constraints.extend([
            ("base hi".into(), base[0].clone()),
            ("base lo".into(), base[1].clone() - 256.expr()),
            ("index hi".into(), index[0].clone() - operands[0][0].clone()),
            ("index lo".into(), index[1].clone() - operands[0][1].clone()),
        ]);
        // pow[0] * 128 = a_hi
        // pow[1] * 128 = a_lo
        // 128 * pow[0/1] no overflow , for pow is 256's index power
        constraints.extend([
            (
                "pow[0] * 128 = a_hi".into(),
                pow[0].clone() * 128.expr() - query_a[0].clone(),
            ),
            (
                "pow[1] * 128 = a_lo".into(),
                pow[1].clone() * 128.expr() - query_a[1].clone(),
            ),
        ]);
        // bitwise lookup constraints
        // operand_1 & a
        // operand_1 operator d  constraints
        let mut query_not_zero_sum = 0.expr();
        for i in 0..4 {
            let entry = config.get_bitwise_lookup(meta, i);
            let (tag, acc, sum) = extract_lookup_expression!(bitwise, entry);
            if i < 2 {
                query_not_zero_sum = query_not_zero_sum + sum;
            }
            // left operand constraints
            let left_operand_constraint = (
                format!("bitwise[{}] left operand = operands[1][{}]", i, i % 2),
                acc[0].clone() - operands[1][i % 2].clone(),
            );
            // right operand constraints
            let right_operand_constraints = if i < 2 {
                (
                    format!("bitwise[{}] right operand = query_a[{}]", i, i % 2),
                    acc[1].clone() - query_a[i % 2].clone(),
                )
            } else {
                (
                    format!("bitwise[{}] right operand = query_d[{}]", i, i % 2),
                    acc[1].clone() - query_d[i % 2].clone(),
                )
            };
            // operator constraints
            let operator_constraints = if i < 2 {
                (
                    format!("bitwise[{}] operator = opAnd ", i),
                    tag.clone() - (bitwise::Tag::And as u8).expr(),
                )
            } else {
                (
                    format!("bitwise[{}] operator", i),
                    (1.expr() - query_not_is_zero.expr())
                        * (tag.clone() - (bitwise::Tag::And as u8).expr())
                        + query_not_is_zero.expr()
                            * (tag.clone() - (bitwise::Tag::Or as u8).expr()),
                )
            };
            // constraints
            constraints.extend([
                left_operand_constraint,
                right_operand_constraints,
                operator_constraints,
            ]);
            // i > 2: final_result constraints
            if i > 2 {
                constraints.extend([(
                    format!("stack push[2][{}] = acc[2]", i),
                    acc[2].clone() - operands[2][i % 2].clone(),
                )]);
                // if carry_hi =1 , final_result = operands[1]
                constraints.extend([(
                    format!(
                        "arithmetic_sub_carry_hi= 1 =>  operands[2][{}] = operands[1][{}]",
                        i % 2,
                        i % 2
                    ),
                    arithmetic_operands[6].clone()
                        * (operands[2][i % 2].clone() - operands[1][i % 2].clone()),
                )])
            }
        }
        // query_not_zero constraints
        constraints.extend([(
            "query_not_zero * 128 = query_not_zero_sum".into(),
            query_not_zero_sum.clone() - query_not_is_zero * 128.expr(),
        )]);
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
        //  add bitwise lookups
        let bitwise_lookup_0 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 0));
        let bitwise_lookup_1 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 1));
        let bitwise_lookup_2 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 2));
        let bitwise_lookup_3 = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 3));
        // arithmetic lookup
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        vec![
            ("stack pop operand_0".into(), stack_lookup_0),
            ("stack pop operand_1".into(), stack_lookup_1),
            ("stack push result".into(), stack_lookup_2),
            ("exp result".into(), exp_lookup),
            ("bitwise lookup 0".into(), bitwise_lookup_0),
            ("bitwise lookup 1".into(), bitwise_lookup_1),
            ("bitwise lookup 2".into(), bitwise_lookup_2),
            ("bitwise lookup 3".into(), bitwise_lookup_3),
            ("arithmetic lookup 0".into(), arithmetic_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, operand_0) = current_state.get_pop_stack_row_value(trace);

        let (stack_pop_1, operand_1) = current_state.get_pop_stack_row_value(trace);

        let result = current_state.stack_top.unwrap_or_default();
        let byte_index_max = U256::from(BYTE_MAX_INDEX);
        let (arithmetic_sub_rows, _) = operation::sub::gen_witness(vec![byte_index_max, operand_0]);
        let stack_push_0 = current_state.get_push_stack_row(trace, result);
        let mut bit_wise_rows = vec![];
        let mut exp_rows = vec![];
        // get a = 128 * 256^operand_0
        let (temp_a, _) = U256::from(256).overflowing_pow(operand_0);
        exp_rows.extend(exp::Row::from_operands(
            U256::from(256),
            operand_0.clone(),
            temp_a.clone(),
        ));
        let a: U256 = U256::from(128) * temp_a;
        let a_lo: U256 = a.low_u128().into();
        let a_hi = a >> 128;
        let operand_1_hi_128 = operand_1 >> 128;
        let operand_1_lo_128: U256 = operand_1.low_u128().into();
        let bitwise_lookup1 = bitwise::Row::from_operation::<F>(
            bitwise::Tag::And,
            operand_1_hi_128.as_u128(),
            a_hi.as_u128(),
        );

        let bitwise_lookup2 = bitwise::Row::from_operation::<F>(
            bitwise::Tag::And,
            operand_1_lo_128.as_u128(),
            a_lo.as_u128(),
        );

        // get not_is_zero = (sum((operand_1 & a).as_bytes))/128
        let not_is_zero = (bitwise_lookup1.last().unwrap().sum_2
            + bitwise_lookup2.last().unwrap().sum_2)
            .div(U256::from(128));
        assert!(not_is_zero.is_zero() || (not_is_zero - U256::one()).is_zero());
        let max_u128 = U256::from(2).pow(U256::from(128)) - 1;

        // get b
        // 1. a_lo = 0, then b_lo = 2^128 -1 ;
        // 2. a_lo <> 0, then b_lo = 2*a_lo -1 ;

        let b_lo = if a_lo.is_zero() {
            max_u128.clone()
        } else {
            a_lo * 2 - 1
        };
        // 1. a_hi <> 0 , then b_hi = 2*a_hi -1
        // 2. a.hi = 0, a_lo = 0, then b_hi = 2^128 -1;
        // 3. a_hi = 0, a_lo <> 0, then b_hi = 0;
        let b_hi = if a_hi.is_zero() {
            if a_lo.is_zero() {
                max_u128.clone()
            } else {
                0.into()
            }
        } else {
            a_hi * 2 - 1
        };

        // get c
        // 1. if a_lo == 0 ,c_lo =0;
        // 2. if a_lo <> 0, c_lo = 2^128 - 2*a_lo
        let c_lo = if a_lo.is_zero() {
            0.into()
        } else {
            max_u128 + 1 - a_lo * 2
        };
        // get c_hi
        let c_hi = if a_hi.is_zero() {
            if a_lo.is_zero() {
                0.into()
            } else {
                max_u128
            }
        } else {
            max_u128 + 1 - a_hi * 2
        };
        // 1.  if not_is_zero = 1 , then d = c, op_result = operand_1 || d
        // 2. if not_is_zero = 0, then d = b , op_result = operand_1 & d
        let d_hi = not_is_zero * c_hi + (U256::one() - not_is_zero) * b_hi;
        let d_lo = not_is_zero * c_lo + (U256::one() - not_is_zero) * b_lo;
        // get bitwise operator tag
        let op_tag = if not_is_zero.is_zero() {
            Tag::And
        } else {
            Tag::Or
        };
        // get bitwise rows
        let bitwise_lookup3 =
            bitwise::Row::from_operation::<F>(op_tag, operand_1_hi_128.as_u128(), d_hi.as_u128());
        let bitwise_lookup4 =
            bitwise::Row::from_operation::<F>(op_tag, operand_1_lo_128.as_u128(), d_lo.low_u128());

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
        core_row_2.insert_bitwise_lookups(0, &bitwise_lookup1.last().unwrap());
        core_row_2.insert_bitwise_lookups(1, &bitwise_lookup2.last().unwrap());
        core_row_2.insert_bitwise_lookups(2, &bitwise_lookup3.last().unwrap());
        core_row_2.insert_bitwise_lookups(3, &bitwise_lookup4.last().unwrap());

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(U256::from(256), operand_0, temp_a);
        let mut core_row_0 = ExecutionState::SIGNEXTEND.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // a_hi set core_row_0.vers_27;
        assign_or_panic!(core_row_0.vers_27, a_hi);
        // a_lo set core_row_0.vers_28;
        assign_or_panic!(core_row_0.vers_28, a_lo);
        // d_hi set core_row_0.vers_29
        assign_or_panic!(core_row_0.vers_29, d_hi);
        // d_lo set core_row_0.vers_30
        assign_or_panic!(core_row_0.vers_30, d_lo);
        // not_is_zero set core_row_0.vers_31;
        assign_or_panic!(core_row_0.vers_31, not_is_zero);
        // fill bit_wise_rows
        bit_wise_rows.extend(bitwise_lookup1);
        bit_wise_rows.extend(bitwise_lookup2);
        bit_wise_rows.extend(bitwise_lookup3);
        bit_wise_rows.extend(bitwise_lookup4);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            exp: exp_rows,
            bitwise: bit_wise_rows,
            arithmetic: arithmetic_sub_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(SignextendGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SIGNEXTEND, stack);
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
    fn assign_params() {
        let stack_0 = Stack::from_slice(&[0xFF.into(), 0.into()]);
        let stack_top_0 = U256::MAX;
        run(stack_0, stack_top_0);
        let stack_1 = Stack::from_slice(&[0x7F.into(), 0.into()]);
        let stack_top_1 = U256::from(0x7f);
        run(stack_1, stack_top_1);
        let stack_2 = Stack::from_slice(&[0xFF.into(), 33.into()]);
        let stack_top_2 = U256::from(0xff);
        run(stack_2, stack_top_2);
    }
}
