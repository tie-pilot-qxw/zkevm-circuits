use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{bitwise, exp, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::ops::Div;
const NUM_ROW: usize = 3;
const STACK_POINTER_DELTA: i32 = -1;
const STATE_STAMP_DELTA: u64 = 3;
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
///             final_result = operand_1 operator b
///     
/// BITWISE lookup 4 * 5 columns,every lookup takes 5 columns;
/// four lookups:
///     BW0: operand_1 hi & a hi; 5 columns
///     BW1: operand_1 lo & a lo; 5 columns
///     BW2: operand_1 hi operator b hi; 5 columns
///     BW3: operand_1 lo operator b lo; 5 columns
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
/// |cnt| 8 col   | 8 col   | 8 col                         | 8 col   |
/// +---+---------+---------+-------------------------------+---------+
/// | 2 | BW0 | BW1 | BW2 | BW3 | A_HI | A_LO | D_HI | D_LO |NZ       |  
/// | 1 | STATE0  | STATE1  | STATE2                        | EXP |   |
/// | 0 |       DYNA_SELECTOR   | AUX                                 |
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
        let query_a_hi = meta.query_advice(config.vers[20], Rotation(-2));
        let query_a_lo = meta.query_advice(config.vers[21], Rotation(-2));
        let query_d_hi = meta.query_advice(config.vers[22], Rotation(-2));
        let query_d_lo = meta.query_advice(config.vers[23], Rotation(-2));
        let query_not_is_zero = meta.query_advice(config.vers[24], Rotation(-2));
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
        // stack constraints
        let mut operands = vec![];
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
            operands.extend([value_hi, value_lo]);
        }

        // [hi,lo], every hi/lo means[acc0,acc1,acc2,sum2,tag],
        let mut bit_wise_operands: Vec<Vec<Expression<F>>> = vec![];
        for i in 0..4 {
            let entry = config.get_bitwise_lookup(i, meta);
            let (tag, accs, sum) = extract_lookup_expression!(bitwise, entry);
            let tmp_row = vec![accs[0].clone(), accs[1].clone(), accs[2].clone(), sum, tag];
            bit_wise_operands.push(tmp_row);
        }
        // bitwise lookup constraints
        // operand_1 & a
        // bit_wise_operands[0/1][0] = operand_1 high/low
        // operands[0/1][1] = query_a_hi/lo
        constraints.extend([
            // operands constraint
            (
                "bit_wise_operands[0][0] = operand_1_hi".into(),
                bit_wise_operands[0][0].clone() - operands[2].clone(),
            ),
            (
                "bit_wise_operands[1][0] = operand_1_lo".into(),
                bit_wise_operands[1][0].clone() - operands[3].clone(),
            ),
            (
                "bit_wise_operands[0][1] = query_a_hi".into(),
                bit_wise_operands[0][1].clone() - query_a_hi.clone(),
            ),
            (
                "bit_wise_operands[1][1] = query_a_lo".into(),
                bit_wise_operands[1][1].clone() - query_a_lo.clone(),
            ),
            // tag constraints
            (
                "tag hi= opAnd".into(),
                bit_wise_operands[0][4].clone() - (bitwise::Tag::And as u8).expr(),
            ),
            (
                "tag lo = opAnd".into(),
                bit_wise_operands[1][4].clone() - (bitwise::Tag::And as u8).expr(),
            ),
        ]);
        // operand_1 operator d  constraints
        // bit_wise_operands[2/3][0] = operand_1_hi/lo
        // bit_wise_operands[2/3][1] = query_d_hi/lo
        constraints.extend([
            // operands constraint
            (
                "bit_wise_operands[2][0] = operand_1_hi".into(),
                bit_wise_operands[2][0].clone() - operands[2].clone(),
            ),
            (
                "bit_wise_operands[3][0] = operand_1_lo".into(),
                bit_wise_operands[3][0].clone() - operands[3].clone(),
            ),
            (
                "bit_wise_operands[2][1] = query_d_hi".into(),
                bit_wise_operands[2][1].clone() - query_d_hi.clone(),
            ),
            (
                "bit_wise_operands[3][1] = query_d_lo".into(),
                bit_wise_operands[3][1].clone() - query_d_lo.clone(),
            ),
            // operator constraints
            (
                "operator constraints".into(),
                (1.expr() - query_not_is_zero.expr())
                    * (bit_wise_operands[2][4].clone() - (bitwise::Tag::And as u8).expr())
                    + query_not_is_zero.expr()
                        * (bit_wise_operands[2][4].clone() - (bitwise::Tag::Or as u8).expr()),
            ),
        ]);
        // final result constraints
        constraints.extend([
            (
                "stack push hi = bitwise acc2 hi".into(),
                operands[4].clone() - bit_wise_operands[2][2].clone(),
            ),
            (
                "stack push lo = bitwise acc2 lo".into(),
                operands[5].clone() - bit_wise_operands[3][2].clone(),
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
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        //  add bitwise lookups
        let bitwise_lookup_0 = query_expression(meta, |meta| config.get_bit_op_lookup(meta, 0));
        let bitwise_lookup_1 = query_expression(meta, |meta| config.get_bit_op_lookup(meta, 1));
        let bitwise_lookup_2 = query_expression(meta, |meta| config.get_bit_op_lookup(meta, 2));
        let bitwise_lookup_3 = query_expression(meta, |meta| config.get_bit_op_lookup(meta, 3));

        vec![
            ("stack pop operand_0".into(), stack_lookup_0),
            ("stack pop operand_1".into(), stack_lookup_1),
            ("stack push result".into(), stack_lookup_2),
            ("exp result".into(), exp_lookup),
            ("bitwise lookup 0".into(), bitwise_lookup_0),
            ("bitwise lookup 1".into(), bitwise_lookup_1),
            ("bitwise lookup 2".into(), bitwise_lookup_2),
            ("bitwise lookup 3".into(), bitwise_lookup_3),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, operand_0) = current_state.get_pop_stack_row_value(trace);

        let (stack_pop_1, operand_1) = current_state.get_pop_stack_row_value(trace);

        let result = current_state.stack_top.unwrap_or_default();

        let stack_push_0 = current_state.get_push_stack_row(trace, result);
        let mut bit_wise_rows = vec![];
        let mut exp_rows = vec![];
        // get a = 128 * 256^operand_0
        let temp_a = U256::from(256).pow(operand_0);
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
        let not_is_zero = (bitwise_lookup1[bitwise_lookup1.len() - 1].sum_2
            + bitwise_lookup2[bitwise_lookup2.len() - 1].sum_2)
            .div(U256::from(128));

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
        // 1.  if not_is_zero = 1 , then d = c, op_result = operand_1 || b
        // 2. if not_is_zero = 0, then d = b , op_result = operand_1 & b
        let d_hi = not_is_zero * c_hi + (U256::from(1) - not_is_zero) * b_hi;
        let d_lo = not_is_zero * c_lo + (U256::from(1) - not_is_zero) * b_lo;
        let mut bitwise_lookup3: Vec<bitwise::Row> = vec![];
        let mut bitwise_lookup4: Vec<bitwise::Row> = vec![];
        if not_is_zero.is_zero() {
            bitwise_lookup3 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::And,
                operand_1_hi_128.as_u128(),
                d_hi.as_u128(),
            );
            bitwise_lookup4 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::And,
                operand_1_lo_128.as_u128(),
                d_lo.low_u128(),
            );
        } else {
            bitwise_lookup3 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::Or,
                operand_1_hi_128.as_u128(),
                d_hi.low_u128(),
            );
            bitwise_lookup4 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::Or,
                operand_1_lo_128.as_u128(),
                d_lo.low_u128(),
            );
        };

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_bitwise_lookups(0, &bitwise_lookup1[bitwise_lookup1.len() - 1]);
        core_row_2.insert_bitwise_lookups(1, &bitwise_lookup2[bitwise_lookup2.len() - 1]);
        core_row_2.insert_bitwise_lookups(2, &bitwise_lookup3[bitwise_lookup3.len() - 1]);
        core_row_2.insert_bitwise_lookups(3, &bitwise_lookup4[bitwise_lookup4.len() - 1]);
        // a_hi set core_row_2.vers_20;
        core_row_2.vers_20 = Some(a_hi);
        // a_lo set core_row_2.vers_21;
        core_row_2.vers_21 = Some(a_lo);
        // d_hi set core_row_2.vers_22
        core_row_2.vers_22 = Some(d_hi);
        // d_lo set core_row_2.vers_23
        core_row_2.vers_23 = Some(d_lo);
        // not_is_zero set core_row_2.vers_24;
        core_row_2.vers_24 = Some(not_is_zero);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(U256::from(256), operand_0, temp_a);
        let core_row_0 = ExecutionState::SIGNEXTEND.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
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
    }
}
