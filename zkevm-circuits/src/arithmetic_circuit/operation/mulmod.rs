use crate::arithmetic_circuit::operation::{
    get_div_mod, get_lt_word_operations, get_mul512, get_mul_add, get_mul_add_word, get_row,
    get_u16s, get_u16s_hi_lo, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::simple_mul::SimpleMulGadget;
use gadgets::simple_mul_512::SimpleMul512Gadget;
use gadgets::util::{expr_from_u16s, split_u256_hi_lo, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Construct the MulModGadget that checks a * b== r (mod n) ,
/// where a, b, n, r are 256-bit words.
/// We have the following equation:
/// `k1 * n + a_remainder = a`
/// `a_remainder * b + 0 = e + d * 2^256`
/// `k2 * n + r = e + d * 2^256`
/// We split it into three equations so that each operand appearing in the process is within the 256-bit range,
/// and we split a 512-bit operation into three simpler 256-bit operations.
pub(crate) struct MulModGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for MulModGadget<F> {
    fn name(&self) -> &'static str {
        "MULMOD"
    }

    fn tag(&self) -> Tag {
        Tag::Mulmod
    }

    fn num_row(&self) -> usize {
        27
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (27, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // get operations
        let mut constraints = vec![];
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let n = config.get_operand(2)(meta);
        let r = config.get_operand(3)(meta);
        let k1 = config.get_operand(4)(meta);
        let a_remainder = config.get_operand(5)(meta);
        let k1_carry = config.get_operand(6)(meta);
        let a_remainder_diff = config.get_operand(8)(meta);
        let a_rem_lt = config.get_operand(9)(meta);

        // 1.  k1 * n + a_remainder  == a
        let (sum_for_k1_hi, k1_hi_1, k1_hi_2) = get_u16s(config, meta, Rotation::cur());
        let (sum_for_k1_lo, k1_lo_1, k1_lo_2) = get_u16s(config, meta, Rotation::prev());
        let (sum_for_n_hi, n_hi_1, n_hi_2) = get_u16s(config, meta, Rotation(-2));
        let (sum_for_n_lo, n_lo_1, n_lo_2) = get_u16s(config, meta, Rotation(-3));

        let k1_limbs: [Expression<F>; 4] = [k1_lo_1, k1_lo_2, k1_hi_1, k1_hi_2];
        let n_limbs: [Expression<F>; 4] = [n_lo_1, n_lo_2, n_hi_1, n_hi_2];

        let mul = SimpleMulGadget::new(
            k1_limbs,
            n_limbs.clone(),
            [a_remainder[1].clone(), a_remainder[0].clone()],
            [a[1].clone(), a[0].clone()],
            [k1_carry[1].clone(), k1_carry[0].clone()],
        );

        constraints.extend(mul.get_constraints());

        // 1.1 when carrying, ensure that carry_lo is within the 65-bit range
        let carry_lo_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-6))(meta))
            .collect();
        let u16_sum_for_carry_lo = expr_from_u16s(&carry_lo_u16s);
        constraints.push((
            "carry_lo = u16 sum".into(),
            k1_carry[1].clone() - u16_sum_for_carry_lo.clone(),
        ));

        // carry_hi == 0 in division, because 'a' as the dividend is 256-bit
        constraints.push(("carry_hi == 0 ".into(), k1_carry[0].clone()));

        // 1.2 a_remainder < n if n != 0
        let is_lt_lo =
            SimpleLtGadget::new(&a_remainder[1], &n[1], &a_rem_lt[1], &a_remainder_diff[1]);
        let is_lt = SimpleLtWordGadget::new(
            &a_remainder[0],
            &n[0],
            &a_rem_lt[0],
            &a_remainder_diff[0],
            is_lt_lo,
        );

        constraints.extend(is_lt.get_constraints());
        constraints.push((
            "a_remainder < n if n != 0".into(),
            (1.expr() - is_lt.expr()) * (n[0].clone() + n[1].clone()),
        ));

        // 2.`a_remainder * b + 0 = e + d * 2^256 `
        let e = config.get_operand(18)(meta);
        let d = config.get_operand(19)(meta);
        let a_rem_mul_b_carry_2 = config.get_operand(20)(meta);
        let a_rem_mul_b_carry = config.get_operand(21)(meta);

        let (sum_for_a_rem_hi, a_rem_hi_1, a_rem_hi_2) = get_u16s(config, meta, Rotation(-4));
        let (sum_for_a_rem_lo, a_rem_lo_1, a_rem_lo_2) = get_u16s(config, meta, Rotation(-5));
        let (sum_for_b_hi, b_hi_1, b_hi_2) = get_u16s(config, meta, Rotation(-9));
        let (sum_for_b_lo, b_lo_1, b_lo_2) = get_u16s(config, meta, Rotation(-10));

        let a_rem_limbs: [Expression<F>; 4] = [a_rem_lo_1, a_rem_lo_2, a_rem_hi_1, a_rem_hi_2];
        let b_limbs: [Expression<F>; 4] = [b_lo_1, b_lo_2, b_hi_1, b_hi_2];

        let a_rem_mul_512 = SimpleMul512Gadget::new(
            a_rem_limbs,
            b_limbs,
            [0.expr(), 0.expr()], // c is zero
            [
                a_rem_mul_b_carry[1].clone(),   // a_rem_mul_b_carry_0 -- above 128 bit
                a_rem_mul_b_carry[0].clone(),   // a_rem_mul_b_carry_1 -- above 256 bit
                a_rem_mul_b_carry_2[1].clone(), // a_rem_mul_b_carry_2 -- above 384 bit
            ],
            [d[1].clone(), d[0].clone()],
            [e[1].clone(), e[0].clone()],
            "a_remainder * b + 0 = e + d * 2^256".into(),
        );

        constraints.extend(a_rem_mul_512.get_constraints());

        // 2.1 a_rem_mul_b_carry[0..3] is 65 ~ 68bit, use 5 u16s to constrain
        let a_rem_mul_b_carry_u16s = [
            a_rem_mul_b_carry[1].clone(),
            a_rem_mul_b_carry[0].clone(),
            a_rem_mul_b_carry_2[1].clone(),
        ];

        let a_rem_mul_b_carry_2_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-15))(meta))
            .collect();
        let a_rem_mul_b_carry_1_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-16))(meta))
            .collect();
        let a_rem_mul_b_carry_0_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-17))(meta))
            .collect();
        let u16_sum_for_carry = [
            expr_from_u16s(&a_rem_mul_b_carry_0_u16s),
            expr_from_u16s(&a_rem_mul_b_carry_1_u16s),
            expr_from_u16s(&a_rem_mul_b_carry_2_u16s),
        ];

        for i in 0..3 {
            constraints.push((
                format!("a_rem_mul_b_carry_{} = u16 sum", i),
                a_rem_mul_b_carry_u16s[i].clone() - u16_sum_for_carry[i].clone(),
            ));
        }

        // 3. `k2 * n + r = e + d * 2^256`
        let k2n_plus_r_carry_2 = config.get_operand(40)(meta);
        let k2n_plus_r_carry = config.get_operand(41)(meta);

        let (sum_for_k2_hi, k2_hi_1, k2_hi_2) = get_u16s(config, meta, Rotation(-20));
        let (sum_for_k2_lo, k2_lo_1, k2_lo_2) = get_u16s(config, meta, Rotation(-21));
        let k2_limbs = [k2_lo_1, k2_lo_2, k2_hi_1, k2_hi_2];

        let k2_mul_512 = SimpleMul512Gadget::new(
            k2_limbs,
            n_limbs,
            [r[1].clone(), r[0].clone()], // r[1] --> lo, r[0] --> hi
            [
                k2n_plus_r_carry[1].clone(),   // k2_mul_n_carry_0 -- above 128 bit
                k2n_plus_r_carry[0].clone(),   // k2_mul_n_carry_1 -- above 256 bit
                k2n_plus_r_carry_2[1].clone(), // k2_mul_n_carry_2 -- above 384 bit
            ],
            [d[1].clone(), d[0].clone()],
            [e[1].clone(), e[0].clone()],
            "k2 * n + r = e + d * 2^256".into(),
        );

        constraints.extend(k2_mul_512.get_constraints());

        // 3.1 k2n_plus_r_carry[0..3] is 65 ~ 68bit, use 5 u16s to constrain
        let k2n_plus_r_carry_u16s = [
            k2n_plus_r_carry[1].clone(),
            k2n_plus_r_carry[0].clone(),
            k2n_plus_r_carry_2[1].clone(),
        ];

        let k2n_plus_r_carry_2_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-24))(meta))
            .collect();
        let k2n_plus_r_carry_1_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-25))(meta))
            .collect();
        let k2n_plus_r_carry_0_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-26))(meta))
            .collect();
        let u16_sum_for_carry = [
            expr_from_u16s(&k2n_plus_r_carry_0_u16s),
            expr_from_u16s(&k2n_plus_r_carry_1_u16s),
            expr_from_u16s(&k2n_plus_r_carry_2_u16s),
        ];

        for i in 0..3 {
            constraints.push((
                format!("k2n_plus_r_carry_{} = u16 sum", i),
                k2n_plus_r_carry_u16s[i].clone() - u16_sum_for_carry[i].clone(),
            ));
        }

        // 3.2 `r - n = r_diff - r_carry << 256`
        let r_diff = config.get_operand(38)(meta);
        let r_lt = config.get_operand(39)(meta);

        let is_lt_lo = SimpleLtGadget::new(&r[1], &n[1], &r_lt[1], &r_diff[1]);
        let is_lt = SimpleLtWordGadget::new(&r[0], &n[0], &r_lt[0], &r_diff[0], is_lt_lo);

        constraints.extend(is_lt.get_constraints());
        constraints.push((
            "r < n if n != 0".into(),
            (1.expr() - is_lt.expr()) * (n[0].clone() + n[1].clone()),
        ));

        // 4. 128-bit range constraints
        let k2 = config.get_operand(36)(meta);
        let (sum_for_a_rem_diff_hi, _, _) = get_u16s(config, meta, Rotation(-7));
        let (sum_for_a_rem_diff_lo, _, _) = get_u16s(config, meta, Rotation(-8));
        let (sum_for_e_hi, _, _) = get_u16s(config, meta, Rotation(-11));
        let (sum_for_e_lo, _, _) = get_u16s(config, meta, Rotation(-12));
        let (sum_for_d_hi, _, _) = get_u16s(config, meta, Rotation(-13));
        let (sum_for_d_lo, _, _) = get_u16s(config, meta, Rotation(-14));
        let (sum_for_r_diff_hi, _, _) = get_u16s(config, meta, Rotation(-18));
        let (sum_for_r_diff_lo, _, _) = get_u16s(config, meta, Rotation(-19));
        let (sum_for_r_hi, _, _) = get_u16s(config, meta, Rotation(-22));
        let (sum_for_r_lo, _, _) = get_u16s(config, meta, Rotation(-23));

        let u16_sum_for_k1 = [sum_for_k1_hi, sum_for_k1_lo];
        let u16_sum_for_n = [sum_for_n_hi, sum_for_n_lo];
        let u16_sum_for_a_rem = [sum_for_a_rem_hi, sum_for_a_rem_lo];
        let u16_sum_for_a_rem_diff = [sum_for_a_rem_diff_hi, sum_for_a_rem_diff_lo];
        let u16_sum_for_b = [sum_for_b_hi, sum_for_b_lo];
        let u16_sum_for_e = [sum_for_e_hi, sum_for_e_lo];
        let u16_sum_for_d = [sum_for_d_hi, sum_for_d_lo];
        let u16_sum_for_r_diff = [sum_for_r_diff_hi, sum_for_r_diff_lo];
        let u16_sum_for_k2 = [sum_for_k2_hi, sum_for_k2_lo];
        let u16_sum_for_r = [sum_for_r_hi, sum_for_r_lo];

        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };
            constraints.push((
                format!("k1_{} = u16 sum", hi_or_lo),
                k1[i].clone() - u16_sum_for_k1[i].clone(),
            ));
            constraints.push((
                format!("n_{} = u16 sum", hi_or_lo),
                n[i].clone() - u16_sum_for_n[i].clone(),
            ));
            constraints.push((
                format!("a_rem_{} = u16 sum", hi_or_lo),
                a_remainder[i].clone() - u16_sum_for_a_rem[i].clone(),
            ));
            constraints.push((
                format!("a_rem_diff_{} = u16 sum", hi_or_lo),
                a_remainder_diff[i].clone() - u16_sum_for_a_rem_diff[i].clone(),
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
            constraints.push((
                format!("r_diff_{} = u16 sum", hi_or_lo),
                r_diff[i].clone() - u16_sum_for_r_diff[i].clone(),
            ));
            constraints.push((
                format!("k2_{} = u16 sum", hi_or_lo),
                k2[i].clone() - u16_sum_for_k2[i].clone(),
            ));
            constraints.push((
                format!("r_{} = u16 sum", hi_or_lo),
                r[i].clone() - u16_sum_for_r[i].clone(),
            ));
        }

        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(3, operands.len());

    let mut mul_mod_cal = MulModCalculator::new(operands[0], operands[1], operands[2]);
    let mul_add_rows = mul_mod_cal.get_mul_add_rows();
    let mul512_first_rows = mul_mod_cal.get_first_mul512_rows();
    let mul512_second_rows = mul_mod_cal.get_second_mul512_rows();

    let mut rows: Vec<Row> = vec![];
    rows.extend(mul512_second_rows);
    rows.extend(mul512_first_rows);
    rows.extend(mul_add_rows);

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
    k1: U256,
    k2: U256,
    r: U256,
    e: U256,
    d: U256,
    a_remainder: U256,
}

impl MulModCalculator {
    /// Return new MulModCalculator
    fn new(a: U256, b: U256, n: U256) -> Self {
        Self {
            a,
            b,
            n,
            ..Default::default()
        }
    }

    /// 1.`a/n = k1 (r) a_remainder`
    fn get_mul_add_rows(&mut self) -> Vec<Row> {
        let a = get_real_value(vec![self.a, self.n]);
        let b = split_u256_hi_lo(&self.b);
        let n = split_u256_hi_lo(&self.n);
        let (k1, a_remainder) = get_div_mod(vec![self.a, U256::zero(), self.n], true);

        self.k1 = k1;
        self.a_remainder = a_remainder;

        // 1.1 `k1 * n + a_remainder = a`
        let k1_carry_hi_lo = get_mul_add(vec![k1, self.n, a_remainder, self.a]);

        // 1.2 `a_remainder - n = a_remainder_diff - a_remainder_carry << 256`
        let (a_rem_lt, ard_split, ard_u16s) = get_lt_word_operations(vec![a_remainder, self.n]);

        // 1.3 `(a_remainder * b) / n = k2 (r) e`
        let (k2, r) = get_div_mod(vec![a_remainder, self.b, self.n], false);
        self.k2 = k2;
        self.r = r;

        let zero = [U256::zero(); 2];

        let a_rem_u16s = get_u16s_hi_lo(a_remainder);
        let k1_u16s = get_u16s_hi_lo(k1);

        let r_split = split_u256_hi_lo(&r);
        let k1_split = split_u256_hi_lo(&k1);
        let a_reminder_split = split_u256_hi_lo(&a_remainder);
        let n_u16s = get_u16s_hi_lo(self.n);
        let k1_carry = [k1_carry_hi_lo[0], k1_carry_hi_lo[1]];
        let a_rem_lt = [(a_rem_lt[0] as u8).into(), (a_rem_lt[1] as u8).into()];
        let k1_carry_lo_u16s = get_u16s_hi_lo(k1_carry_hi_lo[1]);

        let row_0 = get_row(a, b, k1_u16s.0, 0, Tag::Mulmod);
        let row_1 = get_row(n, r_split, k1_u16s.1, 1, Tag::Mulmod);
        let row_2 = get_row(k1_split, a_reminder_split, n_u16s.0, 2, Tag::Mulmod);
        let row_3 = get_row(k1_carry, zero, n_u16s.1, 3, Tag::Mulmod);
        let row_4 = get_row(ard_split, a_rem_lt, a_rem_u16s.0, 4, Tag::Mulmod);
        let row_5 = get_row(zero, zero, a_rem_u16s.1, 5, Tag::Mulmod);
        let row_6 = get_row(zero, zero, k1_carry_lo_u16s.1, 6, Tag::Mulmod);
        let row_7 = get_row(zero, zero, ard_u16s[0].clone(), 7, Tag::Mulmod);
        let row_8 = get_row(zero, zero, ard_u16s[1].clone(), 8, Tag::Mulmod);

        vec![
            row_8, row_7, row_6, row_5, row_4, row_3, row_2, row_1, row_0,
        ]
    }

    /// 2.`a_remainder * b + 0 = e + d * 2^256`
    fn get_first_mul512_rows(&mut self) -> Vec<Row> {
        let (e, d) = get_mul512(vec![self.a_remainder, self.b]);
        let (a_rem_mul_b_carry_0, a_rem_mul_b_carry_1, a_rem_mul_b_carry_2) =
            get_mul_add_word(vec![self.a_remainder, self.b, U256::zero(), e, d]);
        self.e = e;
        self.d = d;

        let e_split = split_u256_hi_lo(&e);
        let d_split = split_u256_hi_lo(&d);

        let e_u16s = get_u16s_hi_lo(e);
        let b_u16s = get_u16s_hi_lo(self.b);
        let d_u16s = get_u16s_hi_lo(d);
        let arb_carry_0_u16s = get_u16s_hi_lo(a_rem_mul_b_carry_0);
        let arb_carry_1_u16s = get_u16s_hi_lo(a_rem_mul_b_carry_1);
        let arb_carry_2_u16s = get_u16s_hi_lo(a_rem_mul_b_carry_2);

        let zero = [U256::zero(); 2];
        let a_rem_carry_2 = [U256::zero(), a_rem_mul_b_carry_2];
        let a_rem_carry = [a_rem_mul_b_carry_1, a_rem_mul_b_carry_0];

        let row_9 = get_row(e_split, d_split, b_u16s.0, 9, Tag::Mulmod);
        let row_10 = get_row(a_rem_carry_2, a_rem_carry, b_u16s.1, 10, Tag::Mulmod);
        let row_11 = get_row(zero, zero, e_u16s.0, 11, Tag::Mulmod);
        let row_12 = get_row(zero, zero, e_u16s.1, 12, Tag::Mulmod);
        let row_13 = get_row(zero, zero, d_u16s.0, 13, Tag::Mulmod);
        let row_14 = get_row(zero, zero, d_u16s.1, 14, Tag::Mulmod);
        let row_15 = get_row(zero, zero, arb_carry_2_u16s.1, 15, Tag::Mulmod);
        let row_16 = get_row(zero, zero, arb_carry_1_u16s.1, 16, Tag::Mulmod);
        let row_17 = get_row(zero, zero, arb_carry_0_u16s.1, 17, Tag::Mulmod);

        vec![
            row_17, row_16, row_15, row_14, row_13, row_12, row_11, row_10, row_9,
        ]
    }

    /// 3.`k2 * n + r = e + d * 2^256`
    fn get_second_mul512_rows(&self) -> Vec<Row> {
        // 3.1 `k2 * n + r = e + d * 2^256`
        let (k2n_plus_r_carry_0, k2n_plus_r_carry_1, k2n_plus_r_carry_2) =
            get_mul_add_word(vec![self.k2, self.n, self.r, self.e, self.d]);
        // 3.2 `r - n = r_diff - r_carry << 256`
        let (r_lt, r_diff_split, r_diff_u16s) = get_lt_word_operations(vec![self.r, self.n]);

        let zero = [U256::zero(); 2];
        let r_lt = [(r_lt[0] as u8).into(), (r_lt[1] as u8).into()];
        let k2n_carry_2 = [U256::zero(), k2n_plus_r_carry_2];
        let k2n_carry = [k2n_plus_r_carry_1, k2n_plus_r_carry_0];
        let k2_split = split_u256_hi_lo(&self.k2);

        let k2_u16s = get_u16s_hi_lo(self.k2);
        let r_u16s = get_u16s_hi_lo(self.r);
        let k2n_carry_0_u16s = get_u16s_hi_lo(k2n_plus_r_carry_0);
        let k2n_carry_1_u16s = get_u16s_hi_lo(k2n_plus_r_carry_1);
        let k2n_carry_2_u16s = get_u16s_hi_lo(k2n_plus_r_carry_2);

        let row_18 = get_row(k2_split, zero, r_diff_u16s[0].clone(), 18, Tag::Mulmod);
        let row_19 = get_row(r_diff_split, r_lt, r_diff_u16s[1].clone(), 19, Tag::Mulmod);
        let row_20 = get_row(k2n_carry_2, k2n_carry, k2_u16s.0, 20, Tag::Mulmod);
        let row_21 = get_row(zero, zero, k2_u16s.1, 21, Tag::Mulmod);
        let row_22 = get_row(zero, zero, r_u16s.0, 22, Tag::Mulmod);
        let row_23 = get_row(zero, zero, r_u16s.1, 23, Tag::Mulmod);
        let row_24 = get_row(zero, zero, k2n_carry_2_u16s.1, 24, Tag::Mulmod);
        let row_25 = get_row(zero, zero, k2n_carry_1_u16s.1, 25, Tag::Mulmod);
        let row_26 = get_row(zero, zero, k2n_carry_0_u16s.1, 26, Tag::Mulmod);

        vec![
            row_26, row_25, row_24, row_23, row_22, row_21, row_20, row_19, row_18,
        ]
    }
}

/// input a, n.
/// if n == 0, return a == 0
/// Setup. a/n = k1 (r) a_remainder
/// if n == 0, then a == 0;
/// we assume that when `n==0`, we set the input `a == 0`
/// in order to optimize subsequent calculations and constraints.
/// we will make constant for this special case at execution.
fn get_real_value(operands: Vec<U256>) -> [U256; 2] {
    assert_eq!(operands.len(), 2);
    let a = if operands[1] == U256::zero() {
        [U256::zero(), U256::zero()]
    } else {
        split_u256_hi_lo(&operands[0])
    };
    a
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
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
    }
}
