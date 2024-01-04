use crate::arithmetic_circuit::operation::{
    get_lt_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, ToLittleEndian, U256};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::util::{pow_of_two, split_u256_hi_lo, Expr};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const SLTSGTRHS: u64 = 32768;
const SLT_N_BYTES: usize = 2;

pub(crate) struct SltSgtGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for SltSgtGadget<F> {
    fn name(&self) -> &'static str {
        "SLTSGT"
    }

    fn tag(&self) -> Tag {
        Tag::SltSgt
    }

    fn num_row(&self) -> usize {
        5
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (5, 1)
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
        // 1. get the u16s sum for a_hi,b_hi,c
        let (u16_sum_for_a_hi, _, _) = get_u16s(config, meta, Rotation(-3));
        let (u16_sum_for_b_hi, _, _) = get_u16s(config, meta, Rotation(-4));
        let (u16_sum_for_c_hi, _, _) = get_u16s(config, meta, Rotation::cur());
        let (u16_sum_for_c_lo, _, _) = get_u16s(config, meta, Rotation::prev());

        //get a_hi_u16,b_hi_u16
        let a_hi_u16 = config.get_u16(0, Rotation(-3))(meta);
        let b_hi_u16 = config.get_u16(0, Rotation(-4))(meta);

        //get a_lt,b_lt
        let a_lt = config.get_u16(0, Rotation(-2))(meta);
        let b_lt = config.get_u16(1, Rotation(-2))(meta);
        let lt = vec![a_lt, b_lt];

        //get a_lt_diff,b_lt_diff
        let a_lt_diff = config.get_u16(2, Rotation(-2))(meta);
        let b_lt_diff = config.get_u16(3, Rotation(-2))(meta);
        let diff = vec![a_lt_diff, b_lt_diff];

        //build a_is_lt and b_is_lt SimpleLtGadget
        let rhs = Expression::Constant(F::from(SLTSGTRHS));
        let a_is_lt: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&a_hi_u16, &rhs, &lt[0], &diff[0]);
        let b_is_lt: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&b_hi_u16, &rhs, &lt[1], &diff[1]);

        let u16_sum_for_c = [u16_sum_for_c_hi, u16_sum_for_c_lo];
        // a and b are signed equal.
        let signed_eq = 1.expr() - (lt[0].clone() - lt[1].clone());

        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };
            let last_overflow = if i == 0 { carry[1].clone() } else { 0.expr() };
            constraints.push((
                format!("c_{} = u16 sum", hi_or_lo),
                c[i].clone() - u16_sum_for_c[i].clone(),
            ));
            constraints.push((
                format!("carry_{} is bool", hi_or_lo),
                carry[i].clone() * (1.expr() - carry[i].clone()),
            ));
            // constraint in the case of all positive numbers
            constraints.push((
                format!(
                    "sub a_{0} + carry_{0} * 2^128 - last_overflow = b_{0} + c_{0} ",
                    hi_or_lo
                ),
                (a[i].clone() + carry[i].clone() * pow_of_two::<F>(128)
                    - last_overflow.clone()
                    - b[i].clone()
                    - c[i].clone())
                    * signed_eq.clone(),
            ));
        }

        //constrain the a_hi and b_hi range
        constraints.push((
            format!("a_hi = u16 sum"),
            a[0].clone() - u16_sum_for_a_hi.clone(),
        ));
        constraints.push((
            format!("b_hi = u16 sum"),
            b[0].clone() - u16_sum_for_b_hi.clone(),
        ));

        constraints.extend(a_is_lt.get_constraints());
        constraints.extend(b_is_lt.get_constraints());

        //constrain if a_lt = 1, then carry_hi = 0 or a_lt = 0.then carry_hi = 1
        constraints.push((
            format!("if a_lt = 1, then carry_hi = 0 or a_lt = 0.then carry_hi = 1"),
            (1.expr() - (lt[0].clone() + carry[0].clone())) * (lt[0].clone() - lt[1].clone()),
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

    /// 1. build a_lt,a_diff b_lt,b_diff. And get a_hi_u16s b_hi_u16s
    let lt_rows = get_lt_rows::<Fr>(&a[0], &b[0]);
    let a_lt = lt_rows[2].u16_0;
    let b_lt = lt_rows[2].u16_1;

    /// 2. If a_lt is not equal to b_lt, then c equals 0. And when a_lt equals 1, carry is set to 0; otherwise, carry is set to 1.
    let (c, carry) = if a_lt != b_lt {
        let c = U256::zero();
        let carry = if a_lt == 1.into() {
            U256::zero()
        } else {
            U256::one()
        };
        (c, carry << 128)
    } else {
        if a_lt == 1.into() {
            let (c, carry_hi) = operands[0].overflowing_sub(operands[1]);
            let (_, carry_lo) = a[1].overflowing_sub(b[1]);
            let carry = (U256::from(carry_hi as u8) << 128) + U256::from(carry_lo as u8);
            (c, carry)
        } else {
            let (c, carry_hi) = operands[1].overflowing_sub(operands[0]);
            let (_, carry_lo) = b[1].overflowing_sub(a[1]);
            let carry = (U256::from(carry_hi as u8) << 128) + U256::from(carry_lo as u8);
            (c, carry)
        }
    };

    let carrys = split_u256_hi_lo(&carry);
    let (carry_hi, carry_lo) = (carrys[0], carrys[1]);

    let mut c_u16s: Vec<u16> = c
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, c_u16s.len());

    let c_split = split_u256_hi_lo(&c);
    let c_hi_u16s = c_u16s.split_off(8);

    let row_0 = get_row(a, b, c_hi_u16s, 0, Tag::SltSgt);
    let row_1 = get_row(c_split, [carry_hi, carry_lo], c_u16s, 1, Tag::SltSgt);

    (
        vec![
            lt_rows[0].clone(),
            lt_rows[1].clone(),
            lt_rows[2].clone(),
            row_1,
            row_0,
        ],
        vec![c, carry],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(SltSgtGadget(PhantomData))
}

fn get_lt_rows<F: Field>(a_lhs: &U256, b_lhs: &U256) -> Vec<Row> {
    let mut a_u16s: Vec<u16> = a_lhs
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, a_u16s.len());
    let _ = a_u16s.split_off(8);

    let mut b_u16s: Vec<u16> = b_lhs
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, b_u16s.len());
    let _ = b_u16s.split_off(8);

    let range = U256::from(2).pow(U256::from(SLT_N_BYTES * 8));
    let (a_lt, a_diff, _) = get_lt_operations(
        &U256::from(a_u16s[0].clone()),
        &U256::from(SLTSGTRHS),
        &range,
    );
    let (b_lt, b_diff, _) = get_lt_operations(
        &U256::from(b_u16s[0].clone()),
        &U256::from(SLTSGTRHS),
        &range,
    );

    let r2_u16s = vec![a_lt as u16, b_lt as u16, 0, 0, 0, 0, 0, 0];

    let mut row_2 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        r2_u16s,
        2,
        Tag::SltSgt,
    );
    row_2.u16_2 = a_diff;
    row_2.u16_3 = b_diff;

    let row_3 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        a_u16s,
        3,
        Tag::SltSgt,
    );

    let row_4 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        b_u16s,
        4,
        Tag::SltSgt,
    );

    vec![row_4, row_3, row_2]
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    fn test_gen_witness_lt_pos() {
        let a = U256::from(u128::MAX) + U256::from(59509090);
        let b = U256::from(u128::MAX) + U256::from(56789);
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();
        assert_eq!(
            // a_lo + carrry_lo = b_lo + c_lo  a_hi + carry_hi << 128 - carry_lo= b_hi + c_hi
            arith[4].operand_0_lo + (arith[3].operand_1_lo << 128),
            arith[4].operand_1_lo + arith[3].operand_0_lo
        );
        println!(
            "{}",
            arith[4].operand_0_hi + (arith[3].operand_1_hi << 128) - arith[3].operand_1_lo
        );
        println!("{}", arith[4].operand_1_hi + arith[3].operand_0_hi);
        assert_eq!(
            arith[4].operand_0_hi + (arith[3].operand_1_hi << 128) - arith[3].operand_1_lo,
            arith[4].operand_1_hi + arith[3].operand_0_hi
        );
        assert_eq!(U256::from(0), result[1] >> 128);
    }

    #[test]
    fn test_gen_witness_lt_neg() {
        let a = U256::MAX - U256::from(59509090);
        let b = U256::MAX - U256::from(590);
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        // b_lo + carry_lo = a_lo + c_lo

        println!(
            "b_lo is {:#x}, carry_lo is {:#x}, a_lo is {:#x}, c_lo is {:#x}",
            arith[4].operand_1_lo,
            arith[3].operand_1_lo,
            arith[4].operand_0_lo,
            arith[3].operand_0_lo
        );
        assert_eq!(
            arith[4].operand_1_lo + (arith[3].operand_1_lo << 128),
            arith[4].operand_0_lo + arith[3].operand_0_lo
        );
        // b_hi + carry_hi << 128 - carry_lo= a_hi + c_hi
        assert_eq!(
            arith[4].operand_1_hi + (arith[3].operand_1_hi << 128) - arith[3].operand_1_lo,
            arith[4].operand_0_hi + arith[3].operand_0_hi
        );
        assert_eq!(U256::from(0), result[1] >> 128);
    }

    #[test]
    fn test_gen_witness_lt_pn() {
        let a = u128::MAX.into();
        let b = U256::MAX - U256::from(3434);
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();

        // c_lo ==c_hi==0
        assert_eq!(arith[3].operand_1_lo + arith[3].operand_1_hi, U256::zero());

        assert_eq!(U256::from(0), result[1] >> 128);
        // test a == b
        let (arithmetic, result) = gen_witness(vec![b, a]);
        assert_eq!(arith[3].operand_1_lo + arith[3].operand_1_hi, U256::zero());

        assert_eq!(U256::from(1), result[1] >> 128);
    }
}
