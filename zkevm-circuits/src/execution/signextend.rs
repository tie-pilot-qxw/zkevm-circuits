use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{bitwise, exp, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
const NUM_ROW: usize = 3;
const STACK_POINTER_DELTA: i32 = -1;
const STATE_STAMP_DELTA: u64 = 3;
/// Signextend gadget
/// algorithm:
/// let u_s_0 ,u_s_1 on stack top,top-1;
/// 1. get a :  a = 128 * 256^u_s_0
/// 2. get u_s_1_t :
///     2.1) let temp_sum = u_s_1 & a;
///     2.2) let u_s_1_t = sum(temp_sum.as_bytes());
/// 3. get b_lo_temp :
///     if a_lo == 0,then b_lo_temp = 2^128 -1;
///     if a_lo <> 0, then b_lo_temp  = 2*a_lo -1;
/// 4. get b_hi_temp :
///     if a_hi <> 0 , then b_hi_temp = 2*a_hi -1;
///     if a.hi = 0, a_lo = 0, then b_hi_temp = 2^128 -1;
///     if a_hi = 0, a_lo <> 0, then b_hi_temp = 0;
/// 5. get final_result :
///     5.1 get b and operator :
///             if u_s_1_t = 128, then b = 2^256 - 1 - (b_hi_temp << 128 + b_lo_temp); operator = &
///             if u_s_1_t = 0, then b = b_hi_temp << 128 + b_low_temp; operator = ||
///     5.2 get final_result :
///             final_result = u_s_1_t operator b
///     
/// BITWISE lookup 4 * 5 columns,every lookup takes 5 columns;
/// four lookups:
///     BW0: u_s_1 hi & a hi; 5 columns
///     BW1: u_s_1 lo & a lo; 5 columns
///     BW2: u_s_1 hi operator b hi; 5 columns
///     BW3: u_s_1 lo operator b lo; 5 columns
/// operator depends u_s_1_t(when 0, operand is &; if 128 operand is ||), which is 0 or 128,
/// AHI: a_hi inverse (algorithm step 1) ,1 column
/// ALI: a_lo inverse (algorithm step 1) ,1 column
/// U_S_1_T: u_s_1_t (algorithm step 2) ,1 column
/// U_S_1_T_INV: u_s_1_t inverse (algorithm step 2) ,1 column  
/// STATE0: u_s_0 lookup , 8 columns
/// STATE1: u_s_1 lookup , 8 columns
/// STATE2: final_result lookup, 8 columns
/// EXP: exp lookup , 6 columns
/// +---+---------+---------+-------------------------------+---------+
/// |cnt| 8 col   | 8 col   | 8 col                         | 8 col   |
/// +---+---------+---------+-------------------------------+---------+
/// | 2 | BW0 | BW1 | BW2 | BW3 |AHI|ALI|U_S_1_T|U_S_1_T_INV|         |  
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
        let query_a_hi_inv = meta.query_advice(config.vers[20], Rotation(-2));
        let query_a_lo_inv = meta.query_advice(config.vers[21], Rotation(-2));
        let query_u_s_1_t = meta.query_advice(config.vers[22], Rotation(-2));
        let query_u_s_1_t_inv = meta.query_advice(config.vers[23], Rotation(-2));
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
        let iszero_a_hi = SimpleIsZero::new(
            &bit_wise_operands[0][1],
            &query_a_hi_inv,
            String::from("a_hi"),
        );
        constraints.extend(iszero_a_hi.get_constraints());
        let iszero_a_lo = SimpleIsZero::new(
            &bit_wise_operands[1][1],
            &query_a_lo_inv,
            String::from("a_lo"),
        );
        constraints.extend(iszero_a_lo.get_constraints());
        let iszero_u_s_1_t =
            SimpleIsZero::new(&query_u_s_1_t, &query_u_s_1_t_inv, String::from("u_s_1_t"));
        constraints.extend(iszero_u_s_1_t.get_constraints());

        // bitwise lookup constraints
        // u_s_1 & a
        // bit_wise_operands[0/1][0] = u_s_1 high/low
        // operands[2/3] = value hi/low
        // bit_wise_operands[0/1][3] = sum2 high/lo 16
        constraints.extend([
            // operands constraint
            (
                "u_s_1[0][0] = value_hi".into(),
                bit_wise_operands[0][0].clone() - operands[2].clone(),
            ),
            (
                "u_s_1[1][0] = value_lo".into(),
                bit_wise_operands[1][0].clone() - operands[3].clone(),
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
        // u_s_1 op b  constraints
        // u_s_1 constraints
        // bit_wise_operands[2/3][0] = u_s_1 high/low
        constraints.extend([
            // operands u_s_1 constraint
            (
                "u_s_1[2][0] = a_hi".into(),
                bit_wise_operands[2][0].clone() - operands[2].clone(),
            ),
            (
                "u_s_1[3][0] = a_lo".into(),
                bit_wise_operands[3][0].clone() - operands[3].clone(),
            ),
        ]);
        // op constraints , if u_s_1_t = 0 , op = and;else op =or
        // operand is bit_wise_operands[2/3][4]
        constraints.extend([
            (
                "bitwise hi operand type".into(),
                (1.expr() - iszero_u_s_1_t.expr())
                    * (bit_wise_operands[2][4].clone() - (bitwise::Tag::Or as u8).expr())
                    + iszero_u_s_1_t.expr()
                        * (bit_wise_operands[2][4].clone() - (bitwise::Tag::And as u8).expr()),
            ),
            (
                "bitwise lo operand type".into(),
                (1.expr() - iszero_u_s_1_t.expr())
                    * (bit_wise_operands[3][4].clone() - (bitwise::Tag::Or as u8).expr())
                    + iszero_u_s_1_t.expr()
                        * (bit_wise_operands[3][4].clone() - (bitwise::Tag::And as u8).expr()),
            ),
        ]);
        // operand b constraints
        // b_hi/b_lo is bit_wise_operands[2/3][1]
        // a_hi/a_lo is bit_wise_operands[0/1][1]
        let max_u128_expr = 1.expr() * pow_of_two::<F>(128) - 1.expr();
        let b_hi_temp_expr = iszero_a_hi.expr()
            * (iszero_a_lo.expr() * max_u128_expr.clone()
                + (1.expr() - iszero_a_lo.expr()) * 0.expr())
            + (1.expr() - iszero_a_hi.expr())
                * (2.expr() * bit_wise_operands[0][1].clone() - 1.expr());
        let b_lo_temp_expr = iszero_a_lo.expr() * max_u128_expr.clone()
            + (1.expr() - iszero_a_lo.expr())
                * (2.expr() * bit_wise_operands[1][1].clone() - 1.expr());
        constraints.extend([
            (
                "bitwise b hi".into(),
                bit_wise_operands[2][1].clone()
                    - (iszero_u_s_1_t.expr() * (b_hi_temp_expr.clone())
                        + (1.expr() - iszero_u_s_1_t.expr())
                            * (max_u128_expr.clone() - b_hi_temp_expr.clone())),
            ),
            (
                "bitwise b lo".into(),
                bit_wise_operands[3][1].clone()
                    - (iszero_u_s_1_t.expr() * b_lo_temp_expr.clone()
                        + (1.expr() - iszero_u_s_1_t.expr())
                            * (max_u128_expr.clone() - b_lo_temp_expr.clone())),
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
        let (stack_pop_0, u_s_0) = current_state.get_pop_stack_row_value(trace);

        let (stack_pop_1, u_s_1) = current_state.get_pop_stack_row_value(trace);

        let result = current_state.stack_top.unwrap_or_default();

        let stack_push_0 = current_state.get_push_stack_row(trace, result);
        let mut bit_wise_rows = vec![];
        let mut exp_rows = vec![];
        // get a = 128 * 256^u_s_0
        let temp_a = U256::from(256).pow(u_s_0);
        exp_rows.extend(exp::Row::from_operands(
            U256::from(256),
            u_s_0.clone(),
            temp_a.clone(),
        ));
        let a: U256 = U256::from(128) * temp_a;
        let a_lo: U256 = a.low_u128().into();
        let a_hi = a >> 128;
        let u_s_1_hi_128 = u_s_1 >> 128;
        let bitwise_lookup1 = bitwise::Row::from_operation::<F>(
            bitwise::Tag::And,
            u_s_1_hi_128.as_u128(),
            a_hi.as_u128(),
        );

        let bitwise_lookup2 =
            bitwise::Row::from_operation::<F>(bitwise::Tag::And, u_s_1.low_u128(), a.low_u128());

        // get u_s_1_t = u_s_1 & a
        // todo use bitwise circuit compute u_s_1_t
        let mut u_s_1_bytes = [0u8; 32];
        let mut a_bytes = [0u8; 32];

        u_s_1.to_little_endian(&mut u_s_1_bytes);
        a.to_little_endian(&mut a_bytes);
        let u_s_1_t: u8 = u_s_1_bytes
            .into_iter()
            .zip(a_bytes.into_iter())
            .map(|(left, right)| left & right)
            .sum();

        let max_u128 = U256::from(2).pow(U256::from(128)) - 1;

        // get b
        // 1. a_lo = 0, then b_lo_temp = 2^128 -1 ;
        // 2. a_lo <> 0, then b_lo_temp = 2*a_lo -1 ;

        let b_lo_temp = if a_lo.is_zero() {
            max_u128.clone()
        } else {
            a_lo * 2 - 1
        };
        // 1. a_hi <> 0 , then b_hi_temp = 2*a_hi -1
        // 2. a.hi = 0, a_lo = 0, then b_hi_temp = 2^128 -1;
        // 3. a_hi = 0, a_lo <> 0, then b_hi_temp = 0;
        let b_hi_temp = if a_hi.is_zero() {
            if a_lo.is_zero() {
                max_u128.clone()
            } else {
                0.into()
            }
        } else {
            a_hi * 2 - 1
        };
        // 1.  if u_s_1_t = 128 , then b = 2^256 - 1 - (b_hi_temp << 128 + b_lo_temp), op_result = u_s_1 & b
        // 2. if u_s_1_t = 0, then b = b_hi_temp << 128 + b_low_temp , op_result = u_s_1 || b
        let mut bitwise_lookup3: Vec<bitwise::Row> = vec![];
        let mut bitwise_lookup4: Vec<bitwise::Row> = vec![];
        let _op_result = if u_s_1_t == 0 {
            bitwise_lookup3 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::And,
                u_s_1_hi_128.as_u128(),
                (b_hi_temp).as_u128(),
            );
            bitwise_lookup4 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::And,
                u_s_1.low_u128(),
                b_lo_temp.low_u128(),
            );
            (bitwise_lookup3[bitwise_lookup3.len() - 1].acc_2 << 128)
                + bitwise_lookup4[bitwise_lookup4.len() - 1].acc_2
        } else {
            let b_hi = max_u128.clone() - b_hi_temp.clone();
            let b_lo = max_u128.clone() - b_lo_temp.clone();
            bitwise_lookup3 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::Or,
                u_s_1_hi_128.as_u128(),
                (b_hi).low_u128(),
            );
            bitwise_lookup4 = bitwise::Row::from_operation::<F>(
                bitwise::Tag::Or,
                u_s_1.low_u128(),
                b_lo.low_u128(),
            );
            (bitwise_lookup3[bitwise_lookup3.len() - 1].acc_2 << 128)
                + bitwise_lookup4[bitwise_lookup4.len() - 1].acc_2
        };

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_bitwise_lookups(0, &bitwise_lookup1[bitwise_lookup1.len() - 1]);
        core_row_2.insert_bitwise_lookups(1, &bitwise_lookup2[bitwise_lookup2.len() - 1]);
        core_row_2.insert_bitwise_lookups(2, &bitwise_lookup3[bitwise_lookup3.len() - 1]);
        core_row_2.insert_bitwise_lookups(3, &bitwise_lookup4[bitwise_lookup4.len() - 1]);
        // a_hi_inv set core_row_2.vers_20;
        let a_hi_f = F::from_u128(a_hi.low_u128());
        let a_hi_inv =
            U256::from_little_endian(a_hi_f.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_2.vers_20 = Some(a_hi_inv);
        // a_lo_inv set core_row_2.vers_21;
        let a_lo_f = F::from_u128(a_lo.low_u128());
        let a_lo_inv =
            U256::from_little_endian(a_lo_f.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_2.vers_21 = Some(a_lo_inv);
        // u_s_1_t set core_row_2.vers_22;
        core_row_2.vers_22 = Some(U256::from(u_s_1_t));
        // u_s_1_t_inv set core_row_2.vers_23;
        core_row_2.vers_23 = Some(U256::from_little_endian(
            F::from(u_s_1_t.into())
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        ));
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        // insert exp lookup
        core_row_1.insert_exp_lookup(U256::from(256), u_s_0, temp_a);
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
