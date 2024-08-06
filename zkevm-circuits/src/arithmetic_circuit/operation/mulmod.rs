// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{
    create_row, get_div_mod_result, get_lt_word_operations, get_mul512_carries, get_mul512_result,
    get_mul768_carries, get_row, get_u16s, get_u16s_hi_lo, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256, U512};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::simple_mul_512::SimpleMul512Gadget;
use gadgets::simple_mul_768::SimpleMul768Gadget;
use gadgets::util::{expr_from_u16s, split_u256_hi_lo, split_u512_hi_lo, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Construct the MulModGadget that checks a * b== r (mod n) ,
/// where a, b, n, r are 256-bit words.
/// We have the following equation:
/// `a * b = n * q + r` q is quotient, r is remainder
/// `a * b = e + d << 256`, e is low 256 bits, d is high 256 bits
/// finally, `n * q + r = e + d << 256`
/// n is 256 bit, q is 512 bit, so, n * q max is 768 bit.
/// We split n,q into N 64bit limbs, so, we have 4 limbs for n, 8 limbs for q
/// assume:
/// `t0 = q0 * n0`
/// `t1 = q0 * n1 + q1 * n0`
/// `t2 = q0 * n2 + q1 * n1 + q2 * n0`
/// `t3 = q0 * n3 + q1 * n2 + q2 * n1 + q3 * n0`
/// `t4 = q1 * n3 + q2 * n2 + q3 * n1 + q4 * n0`
/// `t5 = q2 * n3 + q3 * n2 + q4 * n1 + q5 * n0`
/// `t6 = q3 * n3 + q4 * n2 + q5 * n1 + q6 * n0`
/// `t7 = q4 * n3 + q5 * n2 + q6 * n1 + q7 * n0`
/// `t8 = q5 * n3 + q6 * n2 + q7 * n1`
/// `t9 = q6 * n3 + q7 * n2`
/// `t10 = q7 * n3`
/// so:
/// `t0 + t1 << 64`  <0~128bit>
/// `t2 + t3 << 64` <128~256bit>
/// `t4 + t5 << 64` <256~384bit>
/// `t6 + t7 << 64` <384~512bit>
/// `t8 + t9 << 64` <512~640bit>
/// `t10` <640~768bit>
/// constraints:
/// 1.`n * q + r = e + d << 256`
/// `t0 + t1 << 64 + r_lo = e_lo + carry_0 << 128`
/// `t2 + t3 << 64 + r_hi + carry_0 = e_hi + carry_1 << 128`
/// `t4 + t5 << 64 + carry_1 = d_lo + carry_2 << 128`
/// `t6 + t7 << 64 + carry_2 = d_hi`
/// `(t8 + t9 << 64) + (t10) = 0`
/// 2. `a * b = e + d << 256` mul 512 constraints
/// 3. `r < n if n != 0`
pub(crate) struct MulModGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for MulModGadget<F> {
    fn name(&self) -> &'static str {
        "MULMOD"
    }

    fn tag(&self) -> Tag {
        Tag::Mulmod
    }

    fn num_row(&self) -> usize {
        22
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (22, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        constraints.extend(get_mul_512_constraints(config, meta));
        constraints.extend(get_mul_768_constraints(config, meta));
        constraints
    }
}

/// compute `a * b = e + d << 256`, include constraints:
/// 1. `a * b = e + d << 256` mul 512 constraints
/// 2. `carry_x in 80 bit range`
/// 3. Constraints on u16s for this round of operations
fn get_mul_512_constraints<F: Field>(
    config: &OperationConfig<F>,
    meta: &mut VirtualCells<F>,
) -> Vec<(String, Expression<F>)> {
    // 1.1
    // constraints:
    // `a * b = e + d << 256`
    let mut constraints = vec![];
    let e = config.get_operand(4)(meta);
    let d = config.get_operand(5)(meta);
    let amb_carry_2 = config.get_operand(6)(meta);
    let amb_carry = config.get_operand(7)(meta);

    let (u16s_sum_for_a_hi, a_hi_1, a_hi_2) = get_u16s(config, meta, Rotation::cur());
    let (u16s_sum_for_a_lo, a_lo_1, a_lo_2) = get_u16s(config, meta, Rotation::prev());
    let (u16s_sum_for_b_hi, b_hi_1, b_hi_2) = get_u16s(config, meta, Rotation(-2));
    let (u16s_sum_for_b_lo, b_lo_1, b_lo_2) = get_u16s(config, meta, Rotation(-3));

    let a_limbs = [a_lo_1, a_lo_2, a_hi_1, a_hi_2];
    let b_limbs = [b_lo_1, b_lo_2, b_hi_1, b_hi_2];

    let a_mul_b_512 = SimpleMul512Gadget::new(
        a_limbs,
        b_limbs,
        [0.expr(), 0.expr()], // c is zero
        [
            amb_carry[1].clone(),   // a_rem_mul_b_carry_0 -- above 128 bit
            amb_carry[0].clone(),   // a_rem_mul_b_carry_1 -- above 256 bit
            amb_carry_2[1].clone(), // a_rem_mul_b_carry_2 -- above 384 bit
        ],
        [d[1].clone(), d[0].clone()],
        [e[1].clone(), e[0].clone()],
        "a * b = e + d << 256".into(),
    );
    constraints.extend(a_mul_b_512.get_constraints());

    // 1.2 `carry_x in 80 bit range`
    let amb_carry_0_u16s: Vec<_> = (0..5)
        .map(|i| config.get_u16(i, Rotation(-8))(meta))
        .collect();

    let indexes_and_rotations: Vec<(usize, Rotation)> = (5..8)
        .map(|i| (i, Rotation(-8)))
        .chain((0..2).map(|i| (i, Rotation(-9))))
        .collect();

    let amb_carry_1_u16s: Vec<_> = indexes_and_rotations
        .iter()
        .map(|(i, rotation)| config.get_u16(*i, *rotation)(meta))
        .collect();

    let amb_carry_2_u16s: Vec<_> = (2..7)
        .map(|i| config.get_u16(i, Rotation(-9))(meta))
        .collect();

    let amb_carry_u16s = [
        amb_carry[1].clone(),
        amb_carry[0].clone(),
        amb_carry_2[1].clone(),
    ];

    let u16_sum_for_carry = [
        expr_from_u16s(&amb_carry_0_u16s),
        expr_from_u16s(&amb_carry_1_u16s),
        expr_from_u16s(&amb_carry_2_u16s),
    ];

    for i in 0..3 {
        constraints.push((
            format!("amb_carry_{} = u16 sum", i),
            amb_carry_u16s[i].clone() - u16_sum_for_carry[i].clone(),
        ));
    }

    // 1.3 Constraints on u16s for this round of operations
    // a, b, e, d
    let (u16s_sum_for_e_hi, ..) = get_u16s(config, meta, Rotation(-4));
    let (u16s_sum_for_e_lo, ..) = get_u16s(config, meta, Rotation(-5));
    let (u16s_sum_for_d_hi, ..) = get_u16s(config, meta, Rotation(-6));
    let (u16s_sum_for_d_lo, ..) = get_u16s(config, meta, Rotation(-7));

    let u16_sum_for_a = [u16s_sum_for_a_hi, u16s_sum_for_a_lo];
    let u16_sum_for_b = [u16s_sum_for_b_hi, u16s_sum_for_b_lo];
    let u16_sum_for_e = [u16s_sum_for_e_hi, u16s_sum_for_e_lo];
    let u16_sum_for_d = [u16s_sum_for_d_hi, u16s_sum_for_d_lo];

    let a = config.get_operand(0)(meta);
    let b = config.get_operand(1)(meta);

    for i in 0..2 {
        let hi_or_lo = if i == 0 { "hi" } else { "lo" };
        constraints.push((
            format!("a_{} = u16 sum", hi_or_lo),
            a[i].clone() - u16_sum_for_a[i].clone(),
        ));

        constraints.push((
            format!("b_{} = u16 sum", hi_or_lo),
            b[i].clone() - u16_sum_for_b[i].clone(),
        ));

        constraints.push((
            format!("e_{} = u16 sum", hi_or_lo),
            e[i].clone() - u16_sum_for_e[i].clone(),
        ));

        constraints.push((
            format!("d_{} = u16 sum", hi_or_lo),
            d[i].clone() - u16_sum_for_d[i].clone(),
        ));
    }

    constraints
}

/// compute `n * q + r = e + d << 256`, include constraints:
/// 1. `n * q + r = e + d << 256` mul_768 constraints
/// 2. `carry_x in 80 bit range`
/// 3. `r < n if n != 0`
/// 4. Constraints on u16s for this round of operations
fn get_mul_768_constraints<F: Field>(
    config: &OperationConfig<F>,
    meta: &mut VirtualCells<F>,
) -> Vec<(String, Expression<F>)> {
    // 2.1 `n * q + r = e + d << 256`
    let mut constraints = vec![];
    let (u16s_sum_for_q_lo_0, q_0, q_1) = get_u16s(config, meta, Rotation(-15));
    let (u16s_sum_for_q_lo_1, q_2, q_3) = get_u16s(config, meta, Rotation(-14));
    let (u16s_sum_for_q_hi_0, q_4, q_5) = get_u16s(config, meta, Rotation(-13));
    let (u16s_sum_for_q_hi_1, q_6, q_7) = get_u16s(config, meta, Rotation(-12));
    let (u16s_sum_for_n_lo, n_0, n_1) = get_u16s(config, meta, Rotation(-11));
    let (u16s_sum_for_n_hi, n_2, n_3) = get_u16s(config, meta, Rotation(-10));

    let q_limbs = [q_0, q_1, q_2, q_3, q_4, q_5, q_6, q_7];
    let n_limbs = [n_0, n_1, n_2, n_3];

    let r = config.get_operand(3)(meta);
    let e = config.get_operand(4)(meta);
    let d = config.get_operand(5)(meta);
    let nmq_carry_2 = config.get_operand(22)(meta);
    let nmq_carry = config.get_operand(23)(meta);

    let n_mul_q = SimpleMul768Gadget::new(
        n_limbs,
        q_limbs,
        [r[1].clone(), r[0].clone()],
        [
            nmq_carry[1].clone(),
            nmq_carry[0].clone(),
            nmq_carry_2[1].clone(),
        ],
        [d[1].clone(), d[0].clone()],
        [e[1].clone(), e[0].clone()],
        "n * q + r = e + d << 256".into(),
    );
    constraints.extend(n_mul_q.get_constraints());

    // 2.2 `carry_x in 80 bit range`
    let nmq_carry_0_u16s: Vec<_> = (0..5)
        .map(|i| config.get_u16(i, Rotation(-20))(meta))
        .collect();

    let indexes_and_rotations: Vec<(usize, Rotation)> = (5..8)
        .map(|i| (i, Rotation(-20)))
        .chain((0..2).map(|i| (i, Rotation(-21))))
        .collect();

    let nmq_carry_1_u16s: Vec<_> = indexes_and_rotations
        .iter()
        .map(|(i, rotation)| config.get_u16(*i, *rotation)(meta))
        .collect();

    let nmq_carry_2_u16s: Vec<_> = (2..7)
        .map(|i| config.get_u16(i, Rotation(-21))(meta))
        .collect();

    let nmq_carry_u16s = [
        nmq_carry[1].clone(),
        nmq_carry[0].clone(),
        nmq_carry_2[1].clone(),
    ];

    let u16_sum_for_carry = [
        expr_from_u16s(&nmq_carry_0_u16s),
        expr_from_u16s(&nmq_carry_1_u16s),
        expr_from_u16s(&nmq_carry_2_u16s),
    ];

    for i in 0..3 {
        constraints.push((
            format!("nmq_carry_{} = u16 sum", i),
            nmq_carry_u16s[i].clone() - u16_sum_for_carry[i].clone(),
        ));
    }

    // 2.3 `r < n if n != 0`
    let n = config.get_operand(2)(meta);
    let r_diff = config.get_operand(24)(meta);
    let r_lt = config.get_operand(25)(meta);

    let is_lt_lo = SimpleLtGadget::new(&r[1], &n[1], &r_lt[1], &r_diff[1]);
    let is_lt = SimpleLtWordGadget::new(&r[0], &n[0], &r_lt[0], &r_diff[0], is_lt_lo);
    constraints.extend(is_lt.get_constraints());
    constraints.push((
        "r < n if n != 0".into(),
        (1.expr() - is_lt.expr()) * (n[0].clone() + n[1].clone()),
    ));

    // 2.4 Constraints on u16s for this round of operations
    // q0, q1, q2, q3, r, n, r_n_diff
    let q_hi = config.get_operand(20)(meta);
    let q_lo = config.get_operand(21)(meta);

    let (u16s_sum_for_r_diff_lo, ..) = get_u16s(config, meta, Rotation(-19));
    let (u16s_sum_for_r_diff_hi, ..) = get_u16s(config, meta, Rotation(-18));
    let (u16s_sum_for_r_lo, ..) = get_u16s(config, meta, Rotation(-17));
    let (u16s_sum_for_r_hi, ..) = get_u16s(config, meta, Rotation(-16));

    let u16_sum_for_q = [
        u16s_sum_for_q_hi_1,
        u16s_sum_for_q_hi_0,
        u16s_sum_for_q_lo_1,
        u16s_sum_for_q_lo_0,
    ];
    let u16_sum_for_n = [u16s_sum_for_n_hi, u16s_sum_for_n_lo];
    let u16_sum_for_r = [u16s_sum_for_r_hi, u16s_sum_for_r_lo];
    let u16_sum_for_r_diff = [u16s_sum_for_r_diff_hi, u16s_sum_for_r_diff_lo];

    for i in 0..2 {
        let hi_or_lo = if i == 0 { "hi" } else { "lo" };
        constraints.push((
            format!("n_{} = u16 sum", hi_or_lo),
            n[i].clone() - u16_sum_for_n[i].clone(),
        ));

        constraints.push((
            format!("r_{} = u16 sum", hi_or_lo),
            r[i].clone() - u16_sum_for_r[i].clone(),
        ));

        constraints.push((
            format!("r_diff_{} = u16 sum", hi_or_lo),
            r_diff[i].clone() - u16_sum_for_r_diff[i].clone(),
        ));

        constraints.push((
            format!("q_hi_{} = u16 sum", i),
            q_hi[i].clone() - u16_sum_for_q[i].clone(),
        ));

        constraints.push((
            format!("q_lo_{} = u16 sum", i),
            q_lo[i].clone() - u16_sum_for_q[i + 2].clone(),
        ));
    }

    constraints
}

/// MulMod arithmetic witness rows. (Tag::MulMod)
/// +-----+-------------+-------------+-----------------+-----------------+----------------------------------------+
/// | cnt | o_0_hi      | o_0_lo      | o_1_hi          | o_1_lo          | u16s                                   |
/// +-----+-------------+-------------+-----------------+-----------------+----------------------------------------+
/// | 21  |             |             |                 |                 | n_mul_q_carry_1[0..1] n_mul_q_carry_2[2..6]|
/// | 20  |             |             |                 |                 | n_mul_q_carry_0 [0..4] n_mul_q_carry1 [5..7]|
/// | 19  |             |             |                 |                 | r_n_diff_lo_u16s                       |
/// | 18  |             |             |                 |                 | r_n_diff_hi_u16s                       |
/// | 17  |             |             |                 |                 | r_lo_u16s                              |
/// | 16  |             |             |                 |                 | r_hi_u16s                              |
/// | 15  |             |             |                 |                 | q_0_u16s                               |
/// | 14  |             |             |                 |                 | q_1_u16s                               |
/// | 13  |             |             |                 |                 | q_2_u16s                               |
/// | 12  | r_n_diff_hi | r_n_diff_lo | r_n_lt_hi       | r_n_lt_lo       | q_3_u16s                               |
/// | 11  |             | n_mul_q_carry_2| n_mul_q_carry_1| n_mul_q_carry_0| n_lo_u16s                             |
/// | 10  | q_3         | q_2         | q_1             | q_0             | n_hi_u16s                              |
/// | 9   |             |             |                 |                 | a_mul_b_carry_1[0..1] a_mul_b_carry_2[2..6]|
/// | 8   |             |             |                 |                 | a_mul_b_carry_0 [0..4] a_mul_b_carry1 [5..7]|
/// | 7   |             |             |                 |                 | d_lo_u16s                              |
/// | 6   |             |             |                 |                 | d_hi_u16s                              |
/// | 5   |             |             |                 |                 | e_lo_u16s                              |
/// | 4   |             |             |                 |                 | e_hi_u16s                              |
/// | 3   |             | a_mul_b_carry_2| a_mul_b_carry_1| a_mul_b_carry_0| b_lo_u16s                             |
/// | 2   | e_hi        | e_lo        | d_hi            | d_lo            | b_hi_u16s                              |
/// | 1   | n_hi        | n_lo        | r_hi            | r_lo            | a_lo_u16s                              |
/// | 0   | a_hi        | a_lo        | b_hi            | b_lo            | a_hi_u16s                              |
/// +-----+-------------+-------------+-----------------+-----------------+----------------------------------------+

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(3, operands.len());

    let mut mul_mod_cal = MulModCalculator::new(operands[0], operands[1], operands[2]);
    let mul_512 = mul_mod_cal.get_mul_512_rows();
    let mul_768 = mul_mod_cal.get_mul_add_768_rows();

    let mut rows = vec![];
    rows.extend(mul_768);
    rows.extend(mul_512);

    (rows, vec![mul_mod_cal.r])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(MulModGadget(PhantomData))
}

/// MulModCalculator struct
/// Divide into modules based on formulas,
/// which facilitates troubleshooting and improves code readability.
#[derive(Default, Debug)]
struct MulModCalculator {
    a: U256,
    b: U256,
    n: U256,
    r: U256,
    e: U256,
    d: U256,
    q: U512,
}

impl MulModCalculator {
    /// Return new MulModCalculator
    fn new(a: U256, b: U256, n: U256) -> Self {
        let a = if n == U256::zero() { U256::zero() } else { a };
        Self {
            a,
            b,
            n,
            ..Default::default()
        }
    }

    /// 1.`a * b = e + d << 256`
    fn get_mul_512_rows(&mut self) -> Vec<Row> {
        (self.e, self.d) = get_mul512_result(vec![self.a, self.b]);
        (self.q, self.r) = get_div_mod_result(vec![self.a, self.b, self.n]);

        let (a_mul_b_carry_0, a_mul_b_carry_1, a_mul_b_carry_2) =
            get_mul512_carries(vec![self.a, self.b, U256::zero(), self.e, self.d]);

        let a_split = split_u256_hi_lo(&self.a);
        let b_split = split_u256_hi_lo(&self.b);
        let n_split = split_u256_hi_lo(&self.n);
        let r_split = split_u256_hi_lo(&self.r);
        let e_split = split_u256_hi_lo(&self.e);
        let d_split = split_u256_hi_lo(&self.d);
        let amb_carry_2 = [U256::zero(), a_mul_b_carry_2];
        let amb_carry = [a_mul_b_carry_1, a_mul_b_carry_0];
        let zero = [U256::zero(); 2];

        let a_u16s = get_u16s_hi_lo(self.a);
        let b_u16s = get_u16s_hi_lo(self.b);
        let e_u16s = get_u16s_hi_lo(self.e);
        let d_u16s = get_u16s_hi_lo(self.d);
        let amb_carry_0_u16s = get_u16s_hi_lo(a_mul_b_carry_0);
        let amb_carry_1_u16s = get_u16s_hi_lo(a_mul_b_carry_1);
        let amb_carry_2_u16s = get_u16s_hi_lo(a_mul_b_carry_2);

        let row_0 = get_row(a_split, b_split, a_u16s.0, 0, Tag::Mulmod);
        let row_1 = get_row(n_split, r_split, a_u16s.1, 1, Tag::Mulmod);
        let row_2 = get_row(e_split, d_split, b_u16s.0, 2, Tag::Mulmod);
        let row_3 = get_row(amb_carry_2, amb_carry, b_u16s.1, 3, Tag::Mulmod);
        let row_4 = get_row(zero, zero, e_u16s.0, 4, Tag::Mulmod);
        let row_5 = get_row(zero, zero, e_u16s.1, 5, Tag::Mulmod);
        let row_6 = get_row(zero, zero, d_u16s.0, 6, Tag::Mulmod);
        let row_7 = get_row(zero, zero, d_u16s.1, 7, Tag::Mulmod);

        let row_8 = create_row(
            zero,
            zero,
            Tag::Mulmod,
            8,
            &[
                amb_carry_0_u16s.1[0],
                amb_carry_0_u16s.1[1],
                amb_carry_0_u16s.1[2],
                amb_carry_0_u16s.1[3],
                amb_carry_0_u16s.1[4],
                amb_carry_1_u16s.1[0],
                amb_carry_1_u16s.1[1],
                amb_carry_1_u16s.1[2],
            ],
        );

        let row_9 = create_row(
            zero,
            zero,
            Tag::Mulmod,
            9,
            &[
                amb_carry_1_u16s.1[3],
                amb_carry_1_u16s.1[4],
                amb_carry_2_u16s.1[0],
                amb_carry_2_u16s.1[1],
                amb_carry_2_u16s.1[2],
                amb_carry_2_u16s.1[3],
                amb_carry_2_u16s.1[4],
            ],
        );

        vec![
            row_9, row_8, row_7, row_6, row_5, row_4, row_3, row_2, row_1, row_0,
        ]
    }

    /// 2.`n * q + r = e + d << 256`
    fn get_mul_add_768_rows(&mut self) -> Vec<Row> {
        let q_split = split_u512_hi_lo(&self.q);
        let (n_mul_q_carry_0, n_mul_q_carry_1, n_mul_q_carry_2) =
            get_mul768_carries(vec![self.n, q_split[1], q_split[0], self.r, self.e, self.d]);
        let (r_lt, r_diff_split, r_diff_u16s) = get_lt_word_operations(vec![self.r, self.n]);

        let zero = [U256::zero(); 2];
        let nmq_carry_2 = [U256::zero(), n_mul_q_carry_2];
        let nmq_carry = [n_mul_q_carry_1, n_mul_q_carry_0];
        let r_lt = [(r_lt[0] as u8).into(), (r_lt[1] as u8).into()];
        let q_lo_split = split_u256_hi_lo(&q_split[1]); // 0 => q1, 1 => q0
        let q_hi_split = split_u256_hi_lo(&q_split[0]); // 0 => q3, 1 => q2

        let n_u16s = get_u16s_hi_lo(self.n);
        let q_hi_u16s = get_u16s_hi_lo(q_split[0]);
        let q_lo_u16s = get_u16s_hi_lo(q_split[1]);
        let r_hi_u16s = get_u16s_hi_lo(self.r);
        let nmq_carry_0_u16s = get_u16s_hi_lo(n_mul_q_carry_0);
        let nmq_carry_1_u16s = get_u16s_hi_lo(n_mul_q_carry_1);
        let nmq_carry_2_u16s = get_u16s_hi_lo(n_mul_q_carry_2);

        let row_10 = get_row(q_hi_split, q_lo_split, n_u16s.0, 10, Tag::Mulmod);
        let row_11 = get_row(nmq_carry_2, nmq_carry, n_u16s.1, 11, Tag::Mulmod);
        let row_12 = get_row(r_diff_split, r_lt, q_hi_u16s.0, 12, Tag::Mulmod);
        let row_13 = get_row(zero, zero, q_hi_u16s.1, 13, Tag::Mulmod);
        let row_14 = get_row(zero, zero, q_lo_u16s.0, 14, Tag::Mulmod);
        let row_15 = get_row(zero, zero, q_lo_u16s.1, 15, Tag::Mulmod);
        let row_16 = get_row(zero, zero, r_hi_u16s.0, 16, Tag::Mulmod);
        let row_17 = get_row(zero, zero, r_hi_u16s.1, 17, Tag::Mulmod);
        let row_18 = get_row(zero, zero, r_diff_u16s[0].clone(), 18, Tag::Mulmod);
        let row_19 = get_row(zero, zero, r_diff_u16s[1].clone(), 19, Tag::Mulmod);

        let row_20 = create_row(
            zero,
            zero,
            Tag::Mulmod,
            20,
            &[
                nmq_carry_0_u16s.1[0],
                nmq_carry_0_u16s.1[1],
                nmq_carry_0_u16s.1[2],
                nmq_carry_0_u16s.1[3],
                nmq_carry_0_u16s.1[4],
                nmq_carry_1_u16s.1[0],
                nmq_carry_1_u16s.1[1],
                nmq_carry_1_u16s.1[2],
            ],
        );

        let row_21 = create_row(
            zero,
            zero,
            Tag::Mulmod,
            21,
            &[
                nmq_carry_1_u16s.1[3],
                nmq_carry_1_u16s.1[4],
                nmq_carry_2_u16s.1[0],
                nmq_carry_2_u16s.1[1],
                nmq_carry_2_u16s.1[2],
                nmq_carry_2_u16s.1[3],
                nmq_carry_2_u16s.1[4],
            ],
        );

        vec![
            row_21, row_20, row_19, row_18, row_17, row_16, row_15, row_14, row_13, row_12, row_11,
            row_10,
        ]
    }
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;

    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let b = u128::MAX.into();
        let n = 2.into();
        let (arithmetic, _result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
    }
}
