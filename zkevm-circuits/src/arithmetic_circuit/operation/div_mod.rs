// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{
    get_lt_word_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::simple_lt::SimpleDiffGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, split_u256_limb64, Expr};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// This module contains the implementation of the `DivModGadget` struct and related functions.
/// The `DivModGadget` is used to perform division and modulo operations on 256-bit words.
/// It checks the equation `b * c + d == a, where `a`, `b`, `c`, `d` are 256-bit words.
/// The `DivModGadget` implements the `OperationGadget` trait, which provides methods for constraint generation and witness generation.
/// The `gen_witness` function is used to generate the witness and return the operation result.
/// It takes a vector of operands as input and returns a tuple containing the witness rows and the result of the operation.
///
/// Construct the DivModGadget that checks b * c + d == a (modulo 2**256)(we have a/b = c reminder d,  ==> a = b * c + d),
/// where a, b, c, d,carry are 256-bit words.
/// We execute a multi-limb multiplication as follows:
/// b and c is divided into 4 64-bit limbs, denoted as b0~b3 and c0~c3
/// defined t0, t1, t2, t3
///   t0 = c0 * b0, contribute to 0 ~ 128 bit
///   t1 = c0 * b1 + c1 * b0, contribute to 64 ~ 193 bit (include the carry)
///   t2 = c0 * b2 + c2 * b0 + c1 * b1, contribute to above 128 bit
///   t3 = c0 * b3 + c3 * b0 + c2 * b1 + c1 * b2, contribute to above 192 bit
/// Finally we have:
///  carry_lo = (t0 + (t1 << 64)) + d_lo - a_lo
///  carry_hi = (t2 + (t3 << 64) + carry_lo) + d_hi - a_hi
pub(crate) struct DivModGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for DivModGadget<F> {
    fn name(&self) -> &'static str {
        "DIV_MOD"
    }

    fn tag(&self) -> Tag {
        Tag::DivMod
    }

    fn num_row(&self) -> usize {
        9
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (9, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // get operations

        let mut constraints = vec![];

        // Get the operands from the meta
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let c = config.get_operand(2)(meta); // push value
        let d = config.get_operand(3)(meta);
        let carry = config.get_operand(4)(meta);
        let d_arith = config.get_operand(5)(meta);
        let diff = config.get_operand(12)(meta);
        let lt = config.get_operand(13)(meta);

        // 1. Get the u16s sum for a, b, c, d, and diff, carry_lo
        let (u16_sum_for_diff_hi, _, _) = get_u16s(config, meta, Rotation(-6));
        let (u16_sum_for_diff_lo, _, _) = get_u16s(config, meta, Rotation(-7));
        let (u16_sum_for_d_arith_hi, _, _) = get_u16s(config, meta, Rotation(-4));
        let (u16_sum_for_d_arith_lo, _, _) = get_u16s(config, meta, Rotation(-5));
        let (u16_sum_for_c_hi, c_hi_1, c_hi_2) = get_u16s(config, meta, Rotation(-2));
        let (u16_sum_for_c_lo, c_lo_1, c_lo_2) = get_u16s(config, meta, Rotation(-3));
        let (u16_sum_for_b_hi, b_hi_1, b_hi_2) = get_u16s(config, meta, Rotation::cur());
        let (u16_sum_for_b_lo, b_lo_1, b_lo_2) = get_u16s(config, meta, Rotation::prev());

        let u16_sum_for_b = [u16_sum_for_b_hi, u16_sum_for_b_lo];
        let u16_sum_for_c = [u16_sum_for_c_hi, u16_sum_for_c_lo];
        let u16_sum_for_d_arith = [u16_sum_for_d_arith_hi, u16_sum_for_d_arith_lo];
        let u16_sum_for_diff = [u16_sum_for_diff_hi, u16_sum_for_diff_lo];

        // 2. Calculate the t0, t1, t2, t3 for carry_lo and carry_hi
        let mut c_limbs = vec![];
        let mut b_limbs = vec![];
        c_limbs.extend([c_lo_1, c_lo_2, c_hi_1, c_hi_2]);
        b_limbs.extend([b_lo_1, b_lo_2, b_hi_1, b_hi_2]);

        let t0 = c_limbs[0].clone() * b_limbs[0].clone(); // t0 = c0 * b0
        let t1 = c_limbs[0].clone() * b_limbs[1].clone() + c_limbs[1].clone() * b_limbs[0].clone(); // t1 = c0 * b1 + c1 * b0
        let t2 = c_limbs[0].clone() * b_limbs[2].clone()
            + c_limbs[1].clone() * b_limbs[1].clone()
            + c_limbs[2].clone() * b_limbs[0].clone(); // t2 = c0 * b2 + c1 * b1 + c2 * b0
        let t3 = c_limbs[0].clone() * b_limbs[3].clone()
            + c_limbs[1].clone() * b_limbs[2].clone()
            + c_limbs[2].clone() * b_limbs[1].clone()
            + c_limbs[3].clone() * b_limbs[0].clone(); // t3 = c0 * b3 + c1 * b2 + c2 * b1 + c3 * b0

        // Since there is no overflow in the calculations here, t4, t5, and t6 are all 0.
        let t4 = c_limbs[1].clone() * b_limbs[3].clone()
            + c_limbs[2].clone() * b_limbs[2].clone()
            + c_limbs[3].clone() * b_limbs[1].clone();
        let t5 = c_limbs[2].clone() * b_limbs[3].clone() + c_limbs[3].clone() * b_limbs[2].clone();
        let t6 = c_limbs[3].clone() * b_limbs[3].clone();

        constraints.push((
            "t4 + t5 + t6 == 0".to_string(),
            t4.expr() + t5.expr() + t6.expr(),
        ));

        // Get the u16s sum for carry_lo
        let carry_lo_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-8))(meta))
            .collect();
        let u16_sum_for_carry_lo = expr_from_u16s(&carry_lo_u16s);

        // Constraints that data from operand and u16s sum are equal
        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };
            // Constrain the operand b
            constraints.push((
                format!("b_{} = u16 sum", hi_or_lo),
                b[i].clone() - u16_sum_for_b[i].clone(),
            ));
            // Constrain the operand c
            constraints.push((
                format!("c_{} = u16 sum", hi_or_lo),
                c[i].clone() - u16_sum_for_c[i].clone(),
            ));
            // Constrain the operand d_arith
            constraints.push((
                format!("d_arith{} = u16 sum", hi_or_lo),
                d_arith[i].clone() - u16_sum_for_d_arith[i].clone(),
            ));
            // Constrain the diff range
            constraints.push((
                format!("diff_{} = u16 sum", hi_or_lo),
                diff[i].clone() - u16_sum_for_diff[i].clone(),
            ));
        }

        // When carrying, ensure that carry_lo is within the 65-bit range
        constraints.push((
            "carry_lo = u16 sum".into(),
            carry[1].clone() - u16_sum_for_carry_lo.clone(),
        ));
        // carry_hi == 0 in division, because 'a' as the dividend is 256-bit
        constraints.push(("carry_hi == 0 ".into(), carry[0].clone()));

        // Constraint carry_lo = (t0 + (t1 << 64)) + d_lo - a_lo
        constraints.push((
            format!("(c * b)_lo + d_lo == a_lo + carry_lo * 128"),
            (t0.expr() + (t1.expr() * pow_of_two::<F>(64))) + d_arith[1].clone()
                - a[1].clone()
                - carry[1].clone() * pow_of_two::<F>(128),
        ));
        // Constraint carry_hi = (t2 + (t3 << 64) + carry_lo) + d_hi - a_hi
        constraints.push((
            format!("(c * b)_hi + d_hi + carry_lo == a_hi "),
            (t2.expr() + t3.expr() * pow_of_two::<F>(64)) + d_arith[0].clone() + carry[1].clone()
                - a[0].clone(),
        ));

        let is_lt_lo = SimpleDiffGadget::new(&d_arith[1], &b[1], &lt[1], &diff[1]);
        let is_lt = SimpleLtWordGadget::new(&d_arith[0], &b[0], &lt[0], &diff[0], is_lt_lo);

        // Constraint d_arith < b if b!=0
        constraints.extend(is_lt.get_constraints());
        constraints.push((
            format!("d_arith < b if b!=0 "),
            (b[0].clone() + b[1].clone()) * (1.expr() - is_lt.expr()),
        ));

        // NOTE: When b=0, d_arith is greater than or equal to b;
        //       When b!=0, d_arith is less than b.
        //       Therefore, the expression is_lt is equivalent to b=0 expression.
        // Constrain d = 0, when b == 0
        constraints.push((
            format!("d_hi = 0, when b == 0"),
            (1.expr() - is_lt.expr()) * d[0].clone(),
        ));
        constraints.push((
            format!("d_hi = 0, when b == 0"),
            (1.expr() - is_lt.expr()) * d[1].clone(),
        ));

        // Constrain d = d_arith, when b != 0
        constraints.push((
            format!("d_hi = d_arith_hi, when b != 0"),
            is_lt.expr() * (u16_sum_for_d_arith[1].clone() - d[1].clone()),
        ));
        constraints.push((
            format!("d_lo = d_arith_lo, when b != 0"),
            is_lt.expr() * (u16_sum_for_d_arith[0].clone() - d[0].clone()),
        ));

        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
// witness rows(Tag::Divmod):
// +----------+----------+------------+------------+-----+------------+
// | operand0 | operand1 | operand2   | operand3   | cnt | u16s       |
// +----------+----------+------------+------------+-----+------------+
// |          |          |            |            | 8   | carry_lo   |
// |          |          |            |            | 7   | diff_hi    |
// | diff_hi  | diff_lo  | carry_hi   | carry_lo   | 6   | diff_lo    |
// |          |          |            |            | 5   | d_arith_hi |
// |          |          |            |            | 4   | d_arith_lo |
// |          |          |            |            | 3   | c_lo       |
// | carry_hi | carry_lo | d_arith_hi | d_arith_lo | 2   | c_hi       |
// | c_hi     | c_lo     | d_hi       | d_lo       | 1   | b_lo       |
// | a_hi     | a_lo     | b_hi       | b_lo       | 0   | b_hi       |
// +----------+----------+------------+------------+-----+------------+

pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    // Assert that the number of operands is 2
    assert_eq!(2, operands.len());

    // Get the dividend and divisor
    let a = split_u256_hi_lo(&operands[0]);
    let b = split_u256_hi_lo(&operands[1]);

    // When the divisor b is 0, the EVM stipulates that both the quotient c and the remainder d are 0.
    // For the sake of generality of the constraint, we added the remainder d_arith.
    // When the divisor b is 0, d_arith equals the dividend a.
    // For example, when calculating 9/0, d = 0 and d_arith = 9.
    // When calculating 9/2, d = 1 and d_arith = 1.
    let (c, d) = if operands[1] == U256::zero() {
        (U256::zero(), U256::zero())
    } else {
        operands[0].div_mod(operands[1])
    };
    let d_arith = if operands[1] == U256::zero() {
        operands[0]
    } else {
        d.clone()
    };

    // row 0 and row 1
    // +----------+----------+------------+------------+-----+------------+
    // | c_hi     | c_lo     | d_hi       | d_lo       | 1   | b_lo       |
    // | a_hi     | a_lo     | b_hi       | b_lo       | 0   | b_hi       |
    // +----------+----------+------------+------------+-----+------------+
    let mut b_u16s: Vec<u16> = operands[1]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, b_u16s.len());

    let mut c_u16s: Vec<u16> = c
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, c_u16s.len());

    let mut d_arith_u16s: Vec<u16> = d_arith
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let c_split = split_u256_hi_lo(&c);
    let d_split = split_u256_hi_lo(&d);

    let b_hi_u16s = b_u16s.split_off(8);

    let row_0 = get_row(a, b, b_hi_u16s, 0, Tag::DivMod);
    let row_1 = get_row(c_split, d_split, b_u16s, 1, Tag::DivMod);

    // row 2
    // +----------+----------+------------+------------+-----+------------+
    // | carry_hi | carry_lo | d_arith_hi | d_arith_lo | 2   | c_hi       |
    // +----------+----------+------------+------------+-----+------------+
    // Calculate the overflow of multiplication. carry_hi and carry_lo
    let c_limbs = split_u256_limb64(&c);
    let b_limbs = split_u256_limb64(&operands[1]);
    let d_arith_split = split_u256_hi_lo(&d_arith);

    // construct t0, t1, t2, t3
    let t0 = c_limbs[0] * b_limbs[0];
    let t1 = c_limbs[0] * b_limbs[1] + c_limbs[1] * b_limbs[0];
    let t2 = c_limbs[0] * b_limbs[2] + c_limbs[1] * b_limbs[1] + c_limbs[2] * b_limbs[0];
    let t3 = c_limbs[0] * b_limbs[3]
        + c_limbs[1] * b_limbs[2]
        + c_limbs[2] * b_limbs[1]
        + c_limbs[3] * b_limbs[0];

    // calculate carry_lo and carry_hi
    let carry_lo = (t0 + (t1 << 64) + d_arith_split[1]).saturating_sub(a[1]) >> 128;
    let carry_hi = (t2 + (t3 << 64) + d_arith_split[0] + carry_lo).saturating_sub(a[0]) >> 128;

    let c_hi_u16s = c_u16s.split_off(8);
    let row_2 = get_row(
        [carry_hi, carry_lo],
        d_arith_split,
        c_hi_u16s,
        2,
        Tag::DivMod,
    );

    // row 3
    // +----------+----------+------------+------------+-----+------------+
    // |          |          |            |            | 3   | c_lo       |
    // +----------+----------+------------+------------+-----+------------+
    let row_3 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        c_u16s,
        3,
        Tag::DivMod,
    );

    //row 4
    // +----------+----------+------------+------------+-----+------------+
    // |          |          |            |            | 4   | d_arith_lo |
    // +----------+----------+------------+------------+-----+------------+
    let d_arith_hi_u16s = d_arith_u16s.split_off(8);
    let row_4 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        d_arith_hi_u16s,
        4,
        Tag::DivMod,
    );

    // row 5
    // +----------+----------+------------+------------+-----+------------+
    // |          |          |            |            | 5   | d_arith_hi |
    // +----------+----------+------------+------------+-----+------------+
    let row_5 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        d_arith_u16s,
        5,
        Tag::DivMod,
    );

    // get row 6 and row 7
    // +----------+----------+------------+------------+-----+------------+
    // |          |          |            |            | 7   | diff_hi    |
    // | diff_hi  | diff_lo  | carry_hi   | carry_lo   | 6   | diff_lo    |
    // +----------+----------+------------+------------+-----+------------+
    let lt_rows = get_lt_word_rows::<Fr>(vec![d_arith, operands[1]]);

    // row 8
    // +----------+----------+------------+------------+-----+------------+
    // |          |          |            |            | 8   | carry_lo   |
    // +----------+----------+------------+------------+-----+------------+
    let mut carry_lo_u16s: Vec<u16> = carry_lo
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_lo_u16s.len());
    let _ = carry_lo_u16s.split_off(8);
    let row_8 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_lo_u16s,
        8,
        Tag::DivMod,
    );

    // return the rows and the result of the operation
    (
        vec![
            row_8,
            lt_rows[0].clone(),
            lt_rows[1].clone(),
            row_5,
            row_4,
            row_3,
            row_2,
            row_1,
            row_0,
        ],
        vec![d, c],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(DivModGadget(PhantomData))
}

///get d_arith < b rows
fn get_lt_word_rows<F: Field>(operands: Vec<U256>) -> Vec<Row> {
    let (carry, diff_split, diff_u16s) = get_lt_word_operations(operands);

    // row 7
    let row_7 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        diff_u16s[1].clone(),
        7,
        Tag::DivMod,
    );

    // row 6
    let row_6 = get_row(
        diff_split,
        [(carry[0] as u8).into(), (carry[1] as u8).into()],
        diff_u16s[0].clone(),
        6,
        Tag::DivMod,
    );

    vec![row_7, row_6]
}

#[cfg(test)]
/// This module contains tests for the `gen_witness`, `get_lt_word_rows`, and `le_to_bytes` functions.
mod test {
    use super::{gen_witness, get_lt_word_rows};
    use crate::witness::Witness;
    use eth_types::{ToLittleEndian, U256};
    use halo2_proofs::halo2curves::bn256::Fr;

    /// Test case for the `gen_witness` function.
    /// This test case is used to test the case where the a is 3 and b is 2^128 - 1.
    /// The result of the division is 0 and the remainder is 3.
    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let b = u128::MAX.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        assert_eq!(result[0], U256::from(3));
        assert_eq!(result[1], U256::from(0));

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
    }

    /// Another test case for the `gen_witness` function.
    /// This test case is used to test the case where the divisor is 0.
    /// The result of the division is 0 and the remainder is 0.
    #[test]
    fn test_gen_witness_1() {
        let a = 3.into();
        let b = 0.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        assert_eq!(result[0], U256::from(0));
        assert_eq!(result[1], U256::from(0));

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
    }

    /// Test case for the `get_lt_word_rows` function.
    #[test]
    fn test_get_lt_rows() {
        let a = U256::MAX;
        let b = u128::MAX.into();

        let rows = get_lt_word_rows::<Fr>(vec![a, b]);
        assert_eq!(2, rows.len());
    }

    /// Test case for the `le_to_bytes` function.
    #[test]
    fn test_le_to_bytes() {
        let c = U256::from(0xf0);
        let diff_u16s: Vec<u16> = c
            .to_le_bytes()
            .chunks(2)
            .map(|x| x[0] as u16 + x[1] as u16 * 256)
            .collect();
        println!("diff_u16s is {:?}", diff_u16s);
    }
}
