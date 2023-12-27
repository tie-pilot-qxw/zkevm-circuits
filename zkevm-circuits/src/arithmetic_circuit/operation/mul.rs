use crate::arithmetic_circuit::operation::{get_row, get_u16s, OperationConfig, OperationGadget};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, ToLittleEndian, U256};
use gadgets::util::{
    expr_from_u16s, pow_of_two, split_u256, split_u256_hi_lo, split_u256_limb64, Expr,
};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Construct the MulGadget that checks a * b == c + carry (modulo 2**256),
/// where a, b, c, carry are 256-bit words.
pub(crate) struct MulGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for MulGadget<F> {
    fn name(&self) -> &'static str {
        "MUL"
    }

    fn tag(&self) -> Tag {
        Tag::Mul
    }

    fn num_row(&self) -> usize {
        8
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (8, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let c = config.get_operand(2)(meta);
        let carry = config.get_operand(3)(meta);
        // step
        // 1. get the u16s sum for a,b,c
        let (u16_sum_for_a_hi, a_hi_1, a_hi_2) = get_u16s(config, meta, Rotation::cur());
        let (u16_sum_for_a_lo, a_lo_1, a_lo_2) = get_u16s(config, meta, Rotation::prev());
        let (u16_sum_for_b_hi, b_hi_1, b_hi_2) = get_u16s(config, meta, Rotation(-2));
        let (u16_sum_for_b_lo, b_lo_1, b_lo_2) = get_u16s(config, meta, Rotation(-3));
        let (u16_sum_for_c_hi, _, _) = get_u16s(config, meta, Rotation(-4));
        let (u16_sum_for_c_lo, _, _) = get_u16s(config, meta, Rotation(-5));

        //get the u16s sum for carry_hi and carry_lo
        let mut carry_hi_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-6))(meta))
            .collect();
        let u16_sum_for_carry_hi = expr_from_u16s(&carry_hi_u16s);

        let mut carry_lo_u16s: Vec<_> = (0..5)
            .map(|i| config.get_u16(i, Rotation(-7))(meta))
            .collect();
        let u16_sum_for_carry_lo = expr_from_u16s(&carry_lo_u16s);

        let u16_sum_for_a = [u16_sum_for_a_hi, u16_sum_for_a_lo];
        let u16_sum_for_b = [u16_sum_for_b_hi, u16_sum_for_b_lo];
        let u16_sum_for_c = [u16_sum_for_c_hi, u16_sum_for_c_lo];
        let u16_sum_for_carry = [u16_sum_for_carry_hi, u16_sum_for_carry_lo];
        // 2. calculate the t0,t1,t2,t3 for carry_lo and carry_hi.
        /// We execute a multi-limb multiplication as follows:
        /// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
        /// defined t0, t1, t2, t3
        ///   t0 = a0 * b0, contribute to 0 ~ 128 bit
        ///   t1 = a0 * b1 + a1 * b0, contribute to 64 ~ 193 bit (include the carry)
        ///   t2 = a0 * b2 + a2 * b0 + a1 * b1, contribute to above 128 bit
        ///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, contribute to above 192 bit
        ///
        /// Finally we have:
        ///  carry_lo = ((t0 + (t1 << 64)) - c_lo) >>128 (contribute to 65 bit)
        ///  carry_hi = ((t2 + (t3 << 64) + carry_lo) - c_hi) >> 128 (contribute to 66 bit)
        let mut a_limbs = vec![];
        let mut b_limbs = vec![];
        a_limbs.push(a_lo_1);
        a_limbs.push(a_lo_2);
        a_limbs.push(a_hi_1);
        a_limbs.push(a_hi_2);

        b_limbs.push(b_lo_1);
        b_limbs.push(b_lo_2);
        b_limbs.push(b_hi_1);
        b_limbs.push(b_hi_2);

        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();

        //constraints
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
                format!("c_{} = u16 sum", hi_or_lo),
                c[i].clone() - u16_sum_for_c[i].clone(),
            ));
            //The reason for carry lookup is that carry_lo or carry_hi needs to be shifted 128 bits to the left during calculation,
            //because the characteristics of the finite field may have a value of carry_lo or carry_hi between 0 and 128 bits after left shift
            constraints.push((
                format!("carry_{} = u16 sum", hi_or_lo),
                carry[i].clone() - u16_sum_for_carry[i].clone(),
            ));
        }

        constraints.push((
            format!("(a * b)_lo == c_lo + carry_lo ⋅ 2^128"),
            t0.expr() + (t1.expr() * pow_of_two::<F>(64))
                - (c[1].clone() + carry[1].clone() * pow_of_two::<F>(128)),
        ));
        constraints.push((
            format!("(a * b)_hi + carry_lo == c_hi + carry_hi ⋅ 2^128"),
            (t2.expr() + t3.expr() * pow_of_two::<F>(64)) + carry[1].clone()
                - (c[0].clone() + carry[0].clone() * pow_of_two::<F>(128)),
        ));
        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(2, operands.len());
    let a = split_u256_hi_lo(&operands[0]);
    let b = split_u256_hi_lo(&operands[1]);
    let (c, _) = operands[0].overflowing_mul(operands[1]);
    // Calculate the overflow of multiplication.
    // carry_hi and carry_lo a_limb and b_limb are 64-bit.
    let a_limbs = split_u256_limb64(&operands[0]);
    let b_limbs = split_u256_limb64(&operands[1]);
    let (c_lo, c_hi) = split_u256(&c);

    let t0 = a_limbs[0] * b_limbs[0];
    let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
    let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
    let t3 = a_limbs[0] * b_limbs[3]
        + a_limbs[1] * b_limbs[2]
        + a_limbs[2] * b_limbs[1]
        + a_limbs[3] * b_limbs[0];

    let carry_lo = (t0 + (t1 << 64)).saturating_sub(c_lo) >> 128;
    let carry_hi = (t2 + (t3 << 64) + carry_lo).saturating_sub(c_hi) >> 128;

    let mut a_u16s: Vec<u16> = operands[0]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, a_u16s.len());

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

    let mut carry_lo_u16s: Vec<u16> = carry_lo
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_lo_u16s.len());

    let mut carry_hi_u16s: Vec<u16> = carry_hi
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_hi_u16s.len());

    let a_hi_u16s = a_u16s.split_off(8);
    let row_0 = get_row(a, b, a_hi_u16s, 0, Tag::Mul);

    let c_split = split_u256_hi_lo(&c);
    let row_1 = get_row(c_split, [carry_hi, carry_lo], a_u16s, 1, Tag::Mul);

    let b_hi_u16s = b_u16s.split_off(8);
    let row_2 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        b_hi_u16s,
        2,
        Tag::Mul,
    );
    let row_3 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        b_u16s,
        3,
        Tag::Mul,
    );

    let c_hi_u16s = c_u16s.split_off(8);
    let row_4 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        c_hi_u16s,
        4,
        Tag::Mul,
    );

    let row_5 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        c_u16s,
        5,
        Tag::Mul,
    );
    //
    let _ = carry_hi_u16s.split_off(5);
    carry_hi_u16s.extend(vec![0; 3]);
    let row_6 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_hi_u16s,
        6,
        Tag::Mul,
    );

    let _ = carry_lo_u16s.split_off(5);
    carry_lo_u16s.extend(vec![0; 3]);
    let row_7 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_lo_u16s,
        7,
        Tag::Mul,
    );

    let carry = (carry_hi << 128) + carry_lo;
    (
        vec![row_7, row_6, row_5, row_4, row_3, row_2, row_1, row_0],
        vec![c, carry],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(MulGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let b = u128::MAX.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
    }
}
