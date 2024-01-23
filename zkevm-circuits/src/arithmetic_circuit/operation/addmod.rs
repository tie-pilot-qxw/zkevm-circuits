use crate::arithmetic_circuit::operation::{
    get_lt_word_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256, U512};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, split_u256_limb64, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Construct the AddModGadget that checks (a+b)%n == r.
/// We are verifying a, b, n, r where n is the mod value, and r is the remainder.
/// We can transform this constraint into (a+b) = n * q + r.
/// For simplicity, we can have
/// a % n= a_div_n + a_remainder a = n * a_div_n + a_remainder
/// a_remainder + b = a_remainder_plus_b +a_remainder_plus_b_overflow << 256
/// (a_remainder_plus_b + a_remainder_plus_b_overflow << 256 ) % n= b_div_n + r

pub(crate) struct AddModGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for AddModGadget<F> {
    fn name(&self) -> &'static str {
        "AddMod"
    }

    fn tag(&self) -> Tag {
        Tag::Addmod
    }

    fn num_row(&self) -> usize {
        19
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (19, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // get operations
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let n = config.get_operand(2)(meta);
        let r = config.get_operand(3)(meta);
        let a_div_n = config.get_operand(4)(meta);
        let a_remainder = config.get_operand(5)(meta);
        let an_carry = config.get_operand(6)(meta);
        let arn_carry_lt = config.get_operand(7)(meta);
        let arn_diff = config.get_operand(8)(meta);
        let a_remainder_plus_b_overflow = config.get_operand(9)(meta);
        let carry_0_1 = config.get_operand(10)(meta);
        let rn_carry_lt = config.get_operand(11)(meta);
        let rn_diff = config.get_operand(12)(meta);
        let carry_2 = config.get_operand(13)(meta);
        let b_div_n = config.get_operand(14)(meta);
        let a_remainder_plus_b = config.get_operand(15)(meta);

        // get the u16s sum
        let (u16_sum_for_a_div_n_hi, a_div_n_hi_1, a_div_n_hi_2) =
            get_u16s(config, meta, Rotation::cur());
        let (u16_sum_for_a_div_n_lo, a_div_n_lo_1, a_div_n_lo_2) =
            get_u16s(config, meta, Rotation::prev());
        let (u16_sum_for_n_hi, n_hi_1, n_hi_2) = get_u16s(config, meta, Rotation(-2));
        let (u16_sum_for_n_lo, n_lo_1, n_lo_2) = get_u16s(config, meta, Rotation(-3));
        let (u16_sum_for_a_remainder_hi, _, _) = get_u16s(config, meta, Rotation(-4));
        let (u16_sum_for_a_remainder_lo, _, _) = get_u16s(config, meta, Rotation(-5));
        let an_carry_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-6))(meta))
            .collect();
        let u16_sum_for_an_carry = expr_from_u16s(&an_carry_u16s);
        let (u16_sum_for_arn_diff_hi, _, _) = get_u16s(config, meta, Rotation(-7));
        let (u16_sum_for_arn_diff_lo, _, _) = get_u16s(config, meta, Rotation(-8));
        let (u16_sum_for_a_remainder_plus_b_hi, _, _) = get_u16s(config, meta, Rotation(-9));
        let (u16_sum_for_a_remainder_plus_b_lo, _, _) = get_u16s(config, meta, Rotation(-10));
        let (u16_sum_for_r_hi, _, _) = get_u16s(config, meta, Rotation(-11));
        let (u16_sum_for_r_lo, _, _) = get_u16s(config, meta, Rotation(-12));
        let (u16_sum_for_b_div_n_hi, b_div_n_hi_1, b_div_n_hi_2) =
            get_u16s(config, meta, Rotation(-13));
        let (u16_sum_for_b_div_n_lo, b_div_n_lo_1, b_div_n_lo_2) =
            get_u16s(config, meta, Rotation(-14));
        let carry_0_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-15))(meta))
            .collect();
        let u16_sum_for_carry_0 = expr_from_u16s(&carry_0_u16s);
        let carry_1_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-16))(meta))
            .collect();
        let u16_sum_for_carry_1 = expr_from_u16s(&carry_1_u16s);
        let (u16_sum_for_rn_diff_hi, _, _) = get_u16s(config, meta, Rotation(-17));
        let (u16_sum_for_rn_diff_lo, _, _) = get_u16s(config, meta, Rotation(-18));
        let u16_sum_for_a_div_n = [u16_sum_for_a_div_n_hi, u16_sum_for_a_div_n_lo];
        let u16_sum_for_n = [u16_sum_for_n_hi, u16_sum_for_n_lo];
        let u16_sum_for_a_remainder = [u16_sum_for_a_remainder_hi, u16_sum_for_a_remainder_lo];

        let u16_sum_for_arn_diff = [u16_sum_for_arn_diff_hi, u16_sum_for_arn_diff_lo];
        let u16_sum_for_a_remainder_plus_b = [
            u16_sum_for_a_remainder_plus_b_hi,
            u16_sum_for_a_remainder_plus_b_lo,
        ];
        let u16_sum_for_r = [u16_sum_for_r_hi, u16_sum_for_r_lo];
        let u16_sum_for_b_div_n = [u16_sum_for_b_div_n_hi, u16_sum_for_b_div_n_lo];
        let u16_sum_for_rn_diff = [u16_sum_for_rn_diff_hi, u16_sum_for_rn_diff_lo];

        let mut a_div_n_limbs = vec![];
        let mut n_limbs = vec![];
        let mut b_div_n_limbs = vec![];

        a_div_n_limbs.extend([a_div_n_lo_1, a_div_n_lo_2, a_div_n_hi_1, a_div_n_hi_2]);
        n_limbs.extend([n_lo_1, n_lo_2, n_hi_1, n_hi_2]);
        b_div_n_limbs.extend([b_div_n_lo_1, b_div_n_lo_2, b_div_n_hi_1, b_div_n_hi_2]);

        // calculate the tt0, tt1, tt2, tt3 for an_carry_lo, an_carry_hi
        let tt0 = a_div_n_limbs[0].clone() * n_limbs[0].clone();
        let tt1 = a_div_n_limbs[0].clone() * n_limbs[1].clone()
            + a_div_n_limbs[1].clone() * n_limbs[0].clone();
        let tt2 = a_div_n_limbs[0].clone() * n_limbs[2].clone()
            + a_div_n_limbs[2].clone() * n_limbs[0].clone()
            + a_div_n_limbs[1].clone() * n_limbs[1].clone();
        let tt3 = a_div_n_limbs[0].clone() * n_limbs[3].clone()
            + a_div_n_limbs[3].clone() * n_limbs[0].clone()
            + a_div_n_limbs[2].clone() * n_limbs[1].clone()
            + a_div_n_limbs[1].clone() * n_limbs[2].clone();

        // calculate the t0, t1, t2, t3, t4, t5, t6 for carry_0, carry_1, carry_2
        let t0 = b_div_n_limbs[0].clone() * n_limbs[0].clone();
        let t1 = b_div_n_limbs[0].clone() * n_limbs[1].clone()
            + b_div_n_limbs[1].clone() * n_limbs[0].clone();
        let t2 = b_div_n_limbs[0].clone() * n_limbs[2].clone()
            + b_div_n_limbs[2].clone() * n_limbs[0].clone()
            + b_div_n_limbs[1].clone() * n_limbs[1].clone();
        let t3 = b_div_n_limbs[0].clone() * n_limbs[3].clone()
            + b_div_n_limbs[3].clone() * n_limbs[0].clone()
            + b_div_n_limbs[2].clone() * n_limbs[1].clone()
            + b_div_n_limbs[1].clone() * n_limbs[2].clone();
        let t4 = b_div_n_limbs[1].clone() * n_limbs[3].clone()
            + b_div_n_limbs[2].clone() * n_limbs[2].clone()
            + b_div_n_limbs[3].clone() * n_limbs[1].clone();
        let t5 = b_div_n_limbs[2].clone() * n_limbs[3].clone()
            + b_div_n_limbs[3].clone() * n_limbs[2].clone();
        let t6 = b_div_n_limbs[3].clone() * n_limbs[3].clone();

        // the constraints
        let mut constraints: Vec<(String, Expression<F>)> = vec![];

        // Constrain the u16 sum and the value of the operand.
        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };
            constraints.push((
                format!("a_div_n_{} = u16 sum", hi_or_lo),
                a_div_n[i].clone() - u16_sum_for_a_div_n[i].clone(),
            ));
            constraints.push((
                format!("n_{} = u16 sum", hi_or_lo),
                n[i].clone() - u16_sum_for_n[i].clone(),
            ));
            constraints.push((
                format!("a_remainder_{} = u16 sum", hi_or_lo),
                a_remainder[i].clone() - u16_sum_for_a_remainder[i].clone(),
            ));

            constraints.push((
                format!("arn_diff_{} = u16 sum", hi_or_lo),
                arn_diff[i].clone() - u16_sum_for_arn_diff[i].clone(),
            ));
            constraints.push((
                format!("a_remainder_plus_b_{} = u16 sum", hi_or_lo),
                a_remainder_plus_b[i].clone() - u16_sum_for_a_remainder_plus_b[i].clone(),
            ));
            constraints.push((
                format!("r_{} = u16 sum", hi_or_lo),
                r[i].clone() - u16_sum_for_r[i].clone(),
            ));
            constraints.push((
                format!("b_div_n_{} = u16 sum", hi_or_lo),
                b_div_n[i].clone() - u16_sum_for_b_div_n[i].clone(),
            ));

            constraints.push((
                format!("rn_diff_{} = u16 sum", hi_or_lo),
                rn_diff[i].clone() - u16_sum_for_rn_diff[i].clone(),
            ));
        }

        // Constrain the u16 sum and the value of the carry.
        constraints.push((
            "an_carry_lo = u16 sum".to_string(),
            an_carry[1].clone() - u16_sum_for_an_carry.clone(),
        ));
        constraints.push((
            "an_carry_lo is bool".to_string(),
            an_carry[1].clone() * (1.expr() - an_carry[0].clone()),
        ));
        constraints.push(("an_carry_hi == 0".to_string(), an_carry[0].clone()));

        constraints.push((
            "carry_0 = u16 sum".to_string(),
            carry_0_1[0].clone() - u16_sum_for_carry_0.clone(),
        ));
        constraints.push((
            "carry_1 = u16 sum".to_string(),
            carry_0_1[1].clone() - u16_sum_for_carry_1.clone(),
        ));
        constraints.push(("carry_2 == 0".to_string(), carry_2[0].clone()));

        // Constrain a_remainder <= n
        let is_a_remainder_lt_n_lo =
            SimpleLtGadget::new(&a_remainder[1], &n[1], &arn_carry_lt[1], &arn_diff[1]);
        let a_reminder_lt_n = SimpleLtWordGadget::new(
            &a_remainder[0],
            &n[0],
            &arn_carry_lt[0],
            &arn_diff[0],
            is_a_remainder_lt_n_lo,
        );
        constraints.extend(a_reminder_lt_n.get_constraints());

        constraints.push((
            "an_carry_hi == 0 when n != 0".to_string(),
            (n[0].clone() + n[1].clone()) * an_carry[0].clone(),
        ));

        // Constrain a_remainder + b = a_remainder_plus_b +a_remainder_plus_b_overflow << 256
        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };
            constraints.push((
                format!(
                    "a_remainder_plus_b_{0} + a_remainder_plus_b_overflow_{0} * 2^256 = a_remainder_{0} + b_{0}",
                    hi_or_lo
                ),
                a_remainder_plus_b[i].clone() + a_remainder_plus_b_overflow[i].clone() * pow_of_two::<F>(256)
                    - (a_remainder[i].clone() + b[i].clone()),
            ))
        }

        // Constrain r < n, when n != 0
        let r_lt_n_lo = SimpleLtGadget::new(&r[1], &n[1], &rn_carry_lt[1], &rn_diff[1]);
        let r_lt_n = SimpleLtWordGadget::new(&r[0], &n[0], &rn_carry_lt[0], &rn_diff[0], r_lt_n_lo);
        constraints.extend(r_lt_n.get_constraints());
        constraints.push((
            "r < n, when n != 0".to_string(),
            (1.expr() - r_lt_n.expr()) * (n[0].clone() + n[1].clone()),
        ));

        //  Constrain a_div_n * n + a_remainder == a
        constraints.push((
            format!("(t0 + (t1 << 64)) + a_remainder_lo = an_carry_lo + a_lo"),
            (tt0.expr() + (tt1.expr() * pow_of_two::<F>(64))) + a_remainder[1].clone()
                - (an_carry[1].clone() + a[1].clone()),
        ));
        constraints.push((
            format!("t2 + (t3 << 64) + carry_lo + a_remainder_hi = an_carry_hi + a_hi "),
            (tt2.expr() + (tt3.expr() * pow_of_two::<F>(64))) + a_remainder[0].clone()
                - (an_carry[0].clone() + a[0].clone()),
        ));

        // Constrain b_div_n * n + r == a_remainder_plus_b_overflow * 2**256 + a_remainder_plus_b
        constraints.push((
            "t0 + t1 * 2^64 + r_lo = a_remainder_plus_b_lo + carry_0 * 2^128".to_string(),
            t0.clone() + t1.clone() * pow_of_two::<F>(64) + r[1].clone()
                - (a_remainder_plus_b[1].clone() + carry_0_1[0].clone() * pow_of_two::<F>(128)),
        ));
        constraints.push((
            "t2 + t3 * 2^64 + r_hi + carry_0 = a_remainder_plus_b_hi + carry_1 * 2^128".to_string(),
            t2.clone() + t3.clone() * pow_of_two::<F>(64) + r[0].clone() + carry_0_1[0].clone()
                - (a_remainder_plus_b[0].clone() + carry_0_1[1].clone() * pow_of_two::<F>(128)),
        ));
        constraints.push((
            "t4 + t5 * 2^64 + carry_1 = a_remainder_plus_b_overflow_lo + carry_2 * 2^128"
                .to_string(),
            t4.clone() + t5.clone() * pow_of_two::<F>(64) + carry_0_1[1].clone()
                - (a_remainder_plus_b_overflow[1].clone()
                    + carry_2[0].clone() * pow_of_two::<F>(128)),
        ));
        constraints.push((
            "t6 + carry_2 = a_remainder_plus_b_overflow_hi".to_string(),
            t6.clone() + carry_2[0].clone() - a_remainder_plus_b_overflow[0].clone(),
        ));

        constraints
    }
}

// Addmod arithmetic witeness rows. (Tag::Addmod)
// +-------------+-------------+--------------------------------+--------------------------------+-----+-----------------------+
// | operand_0_hi| operand_0_lo| operand_1_hi                   | operand_1_lo                   | cnt | u16s                  |
// +-------------+-------------+--------------------------------+--------------------------------+-----+-----------------------+
// |             |             |                                |                                | 18  | rn_diff_lo            |
// |             |             |                                |                                | 17  | rn_diff_hi            |
// |             |             |                                |                                | 16  | carry_1               |
// |             |             |                                |                                | 15  | carry_0               |
// |             |             |                                |                                | 14  | b_div_n_lo            |
// |             |             |                                |                                | 13  | b_div_n_hi            |
// |             |             |                                |                                | 12  | r_lo                  |
// |             |             |                                |                                | 11  | r_hi                  |
// |             |             |                                |                                | 10  | a_remainder_plus_b_lo |
// |             |             |                                |                                | 9   | a_remainder_plus_b_hi |
// |             |             |                                |                                | 8   | arn_diff_lo           |
// | b_div_n_hi  | b_div_n_lo  | a_remainder_plus_b_hi          | a_remainder_plus_b_lo          | 7   | arn_diff_hi           |
// | rn_diff_hi  | rn_diff_lo  | carry_2                        |                                | 6   | an_carry_lo           |
// | carry_0     | carry_1     | rn_carry_lt_hi                 | rn_carry_lt_lo                 | 5   | a_remainder_lo        |
// | arn_diff_hi | arn_diff_lo | a_remainder_plus_b_overflow_hi | a_remainder_plus_b_overflow_lo | 4   | a_remainder_hi        |
// | an_carry_hi | an_carry_lo | arn_carry_lt_hi                | arn_carry_lt_lo                | 3   | n_lo                  |
// | a_div_n_hi  | a_div_n_lo  | a_remainder_hi                 | a_remainder_lo                 | 2   | n_hi                  |
// | n_hi        | n_lo        | r_hi                           | r_lo                           | 1   | a_div_n_lo            |
// | a_hi        | a_lo        | b_hi                           | b_lo                           | 0   | a_div_n_hi            |
// +-------------+-------------+--------------------------------+--------------------------------+-----+-----------------------+

/// Generate the addmod witness and return operation result
/// It is called during core circuit's gen_witness。
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(3, operands.len());

    // If n = 0, for the sake of constraint consistency, we also set a and b to be 0.
    let (a_arith, b_arith) = if operands[2] == U256::zero() {
        (0.into(), 0.into())
    } else {
        (operands[0].clone(), operands[1].clone())
    };

    let a = split_u256_hi_lo(&a_arith);
    let b = split_u256_hi_lo(&b_arith);
    let n = split_u256_hi_lo(&operands[2]);

    let (a_div_n, a_remainder) = if operands[2] == U256::zero() {
        (U256::zero(), U256::zero())
    } else {
        a_arith.div_mod(operands[2])
    };

    let (a_remainder_plus_b, a_remainder_plus_b_overflow_flag) =
        a_remainder.overflowing_add(b_arith);
    let a_remainder_plus_b_overflow = if a_remainder_plus_b_overflow_flag {
        U256::one()
    } else {
        U256::zero()
    };

    let (b_div_n, r) = if operands[2] != U256::zero() {
        let (b_div_n_tmp, r_tmp) = (U512::from(a_remainder_plus_b_overflow)
            * (U512::from(1) << 256)
            + U512::from(a_remainder_plus_b))
        .div_mod(U512::from(operands[2]));
        (b_div_n_tmp.try_into().unwrap(), r_tmp.try_into().unwrap())
    } else {
        (U256::zero(), U256::zero())
    };

    // row 0
    let mut a_div_n_u16s: Vec<u16> = a_div_n
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let a_div_n_hi_u16s = a_div_n_u16s.split_off(8);

    let row_0 = get_row(a, b, a_div_n_hi_u16s, 0, Tag::Addmod);

    // row 1
    let r_split = split_u256_hi_lo(&r);

    let row_1 = get_row(n, r_split, a_div_n_u16s, 1, Tag::Addmod);

    // row 2
    let mut n_u16s: Vec<u16> = operands[2]
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let n_hi_u16s = n_u16s.split_off(8);
    let a_div_n_split = split_u256_hi_lo(&a_div_n);
    let a_remainder_split = split_u256_hi_lo(&a_remainder);

    let row_2 = get_row(a_div_n_split, a_remainder_split, n_hi_u16s, 2, Tag::Addmod);

    // row3
    let (arn_carry_lt, arn_diff_split, arn_diff_u16s) =
        get_lt_word_operations(vec![a_remainder.clone(), operands[2].clone()]);

    // Construct the DivModGadget that checks a_div_n * n + a_remainder == a(we have a/n = a_div_n + a_remainder ==> a_div_n * n + a_remainder = a),
    // where a, n, a_remainder, a_div_n,carry are 256-bit words.
    // We execute a multi-limb multiplication as follows:
    // a_div_n and n is divided into 4 64-bit limbs, denoted as a_div_n0~a_div_n3 and n0~n3
    // defined t0, t1, t2, t3
    // t0 = a_div_n0 * n0, contribute to 0 ~ 128 bit
    // t1 = a_div_n0 * n1 + a_div_n1 * n0, contribute to 64 ~ 193 bit (include the carry)
    // t2 = a_div_n0 * n2 + a_div_n2 * n0 + a_div_n1 * n1, contribute to above 128 bit
    // t3 = a_div_n0 * n3 + a_div_n3 * n0 + a_div_n2 * n1 + a_div_n1 * n2, contribute to above 192 bit
    // Finally we have:
    // an_carry_lo = (t0 + (t1 << 64)) + a_remainder_lo - a_lo
    // an_carry_hi = (t2 + (t3 << 64) + carry_lo) + a_remainder_hi - a_hi
    let a_split = split_u256_hi_lo(&a_arith);
    let a_div_n_limbs = split_u256_limb64(&a_div_n);
    let n_limbs = split_u256_limb64(&operands[2]);
    let t0 = a_div_n_limbs[0] * n_limbs[0];
    let t1 = a_div_n_limbs[0] * n_limbs[1] + a_div_n_limbs[1] * n_limbs[0];
    let t2 = a_div_n_limbs[0] * n_limbs[2]
        + a_div_n_limbs[2] * n_limbs[0]
        + a_div_n_limbs[1] * n_limbs[1];
    let t3 = a_div_n_limbs[3] * n_limbs[0]
        + a_div_n_limbs[0] * n_limbs[3]
        + a_div_n_limbs[2] * n_limbs[1]
        + a_div_n_limbs[1] * n_limbs[2];

    let an_carry_lo = (t0 + (t1 << 64) + a_remainder_split[1]).saturating_sub(a_split[1]) >> 128;
    let an_carry_hi = (t2 + (t3 << 64) + a_remainder_split[0]).saturating_sub(a_split[0]) >> 128;

    let row_3 = get_row(
        [an_carry_hi, an_carry_lo],
        [
            (arn_carry_lt[0] as u8).into(),
            (arn_carry_lt[1] as u8).into(),
        ],
        n_u16s,
        3,
        Tag::Addmod,
    );

    // row4
    let mut a_remainder_u16s: Vec<u16> = a_remainder
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let a_remainder_hi_u16s = a_remainder_u16s.split_off(8);
    let a_remainder_plus_b_overflow_split = split_u256_hi_lo(&a_remainder_plus_b_overflow);
    let row_4 = get_row(
        arn_diff_split,
        a_remainder_plus_b_overflow_split,
        a_remainder_hi_u16s,
        4,
        Tag::Addmod,
    );

    //  row5
    // Construct the gadget that checks b_div_n * n + r == a_remainder_plus_b_overflow * 2**256 + a_remainder_plus_b
    // where b_div_n, n, r, a_remainder_plus_b_overflow, a_remainder_plus_b are 256-bit words.
    // We execute a multi-limb multiplication as follows:
    // b_div_n and n is divided into 4 64-bit limbs, denoted as b_div_n0~b_div_n3 and n0~n3
    // defined t0, t1, t2, t3, t4, t5, t6:
    // t0 = b_div_n0 * n0, // 0 - 128bit
    // t1 = b_div_n0 * n1 + b_div_n1 * n0, //64 - 193bit
    // t2 = b_div_n0 * n2 + b_div_n2 * n0 + b_div_n1 * n1, //128 - 258bit
    // t3 = b_div_n0 * n3 + b_div_n3 * n0 + b_div_n2 * n1 + b_div_n1 * n2, //192 - 322bit
    // t4 = b_div_n1 * n3 + b_div_n2 * n2 + b_div_n3 * n1,
    // t5 = b_div_n2 * n3 + b_div_n3 * n2,
    // t6 = b_div_n3 * n3,
    // Finally we just prove:
    // t0 + t1 * 2^64 + r_lo = a_remainder_plus_b_lo + carry_0 * 2^128 // carry_0 is 65bit
    // t2 + t3 * 2^64 + r_hi + carry_0 = a_remainder_plus_b_hi + carry_1 * 2^128
    // t4 + t5 * 2^64 + carry_1 = a_remainder_plus_b_overflow_lo + carry_2 * 2^128
    // t6 + carry_2 = a_remainder_plus_b_overflow_hi
    let b_div_n_limbs = split_u256_limb64(&b_div_n);
    let n_limbs = split_u256_limb64(&operands[2]);
    let t0 = b_div_n_limbs[0] * n_limbs[0];
    let t1 = b_div_n_limbs[0] * n_limbs[1] + b_div_n_limbs[1] * n_limbs[0];
    let t2 = b_div_n_limbs[0] * n_limbs[2]
        + b_div_n_limbs[2] * n_limbs[0]
        + b_div_n_limbs[1] * n_limbs[1];
    let t3 = b_div_n_limbs[0] * n_limbs[3]
        + b_div_n_limbs[3] * n_limbs[0]
        + b_div_n_limbs[2] * n_limbs[1]
        + b_div_n_limbs[1] * n_limbs[2];
    // t4, t5 no need
    let t6 = b_div_n_limbs[3] * n_limbs[3];

    let a_remainder_plus_b_split = split_u256_hi_lo(&a_remainder_plus_b);
    let carry_0 =
        ((t0 + (t1 << 64) + r_split[1]).saturating_sub(a_remainder_plus_b_split[1])) >> 128;
    let carry_1 = ((t2 + (t3 << 64) + r_split[0] + carry_0)
        .saturating_sub(a_remainder_plus_b_split[0]))
        >> 128;
    let carry_2 = a_remainder_plus_b_overflow_split[0] - t6;

    let (rn_carry_lt, rn_diff_split, rn_diff_u16s) =
        get_lt_word_operations(vec![r.clone(), operands[2].clone()]);

    let row_5 = get_row(
        [carry_0, carry_1],
        [(rn_carry_lt[0] as u8).into(), (rn_carry_lt[1] as u8).into()],
        a_remainder_u16s,
        5,
        Tag::Addmod,
    );

    // row6
    let mut an_carry_u16s: Vec<u16> = an_carry_lo
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let _ = an_carry_u16s.split_off(8);

    let row_6 = get_row(
        rn_diff_split,
        [carry_2, U256::zero()],
        an_carry_u16s,
        6,
        Tag::Addmod,
    );

    // row7
    let b_div_n_split = split_u256_hi_lo(&b_div_n);
    let row_7 = get_row(
        b_div_n_split,
        a_remainder_plus_b_split,
        arn_diff_u16s[0].clone(),
        7,
        Tag::Addmod,
    );

    // row8
    let row_8 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        arn_diff_u16s[1].clone(),
        8,
        Tag::Addmod,
    );

    // row9
    let mut a_remainder_plus_b_u16s: Vec<u16> = a_remainder_plus_b
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let a_remainder_plus_b_hi_u16s = a_remainder_plus_b_u16s.split_off(8);

    let row_9 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        a_remainder_plus_b_hi_u16s,
        9,
        Tag::Addmod,
    );

    // row10
    let row_10 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        a_remainder_plus_b_u16s,
        10,
        Tag::Addmod,
    );

    // row11
    let mut r_u16s: Vec<u16> = r
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let r_hi_u16s = r_u16s.split_off(8);

    let row_11 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        r_hi_u16s,
        11,
        Tag::Addmod,
    );

    // row12
    let row_12 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        r_u16s,
        12,
        Tag::Addmod,
    );

    // row13
    let mut b_div_n_u16s: Vec<u16> = b_div_n
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let b_div_n_hi_u16s = b_div_n_u16s.split_off(8);
    let row_13 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        b_div_n_hi_u16s,
        13,
        Tag::Addmod,
    );

    // row14
    let row_14 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        b_div_n_u16s,
        14,
        Tag::Addmod,
    );

    // row15
    let carry_0_u16s: Vec<u16> = carry_0
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let row_15 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_0_u16s,
        15,
        Tag::Addmod,
    );

    // row16
    let carry_1_u16s: Vec<u16> = carry_1
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let row_16 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_1_u16s,
        16,
        Tag::Addmod,
    );

    // row17
    let row_17 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        rn_diff_u16s[0].clone(),
        17,
        Tag::Addmod,
    );

    // row18
    let row_18 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        rn_diff_u16s[1].clone(),
        18,
        Tag::Addmod,
    );

    (
        vec![
            row_18, row_17, row_16, row_15, row_14, row_13, row_12, row_11, row_10, row_9, row_8,
            row_7, row_6, row_5, row_4, row_3, row_2, row_1, row_0,
        ],
        vec![r, U256::zero()],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(AddModGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let b = 4.into();
        let n = 2.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(1));
    }

    #[test]
    fn test_gen_witness_1() {
        let a = 3.into();
        let b = 4.into();
        let n = 0.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
    }

    #[test]
    fn test_gen_witness_2() {
        let a = 3.into();
        let b = U256::MAX;
        let n = 4.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(2));
    }

    #[test]
    fn test_gen_witness_3() {
        let a = 3.into();
        let b = 4.into();
        let n = 1.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
    }

    #[test]
    fn test_gen_witness_4() {
        let a = 0.into();
        let b = 0.into();
        let n = 1.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
    }
}
