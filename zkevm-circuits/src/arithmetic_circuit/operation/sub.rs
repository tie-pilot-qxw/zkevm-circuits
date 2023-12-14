use crate::arithmetic_circuit::operation::{OperationConfig, OperationGadget};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, ToLittleEndian, U256};
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct SubGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for SubGadget<F> {
    fn name(&self) -> &'static str {
        "SUB"
    }

    fn tag(&self) -> Tag {
        Tag::Sub
    }

    fn num_row(&self) -> usize {
        2
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (2, 1)
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
        let u16_sum_for_c_hi = {
            let u16s: Vec<_> = (0..8)
                .map(|i| config.get_u16(i, Rotation::cur())(meta))
                .collect();
            expr_from_u16s(&u16s)
        };
        let u16_sum_for_c_lo = {
            let u16s: Vec<_> = (0..8)
                .map(|i| config.get_u16(i, Rotation::prev())(meta))
                .collect();
            expr_from_u16s(&u16s)
        };
        let u16_sum_for_c = [u16_sum_for_c_hi, u16_sum_for_c_lo];
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
            constraints.push((
                format!(
                    "sub a_{0} + carry_{0} * 2^128 - last_overflow = b_{0} + c_{0}",
                    hi_or_lo
                ),
                a[i].clone() + carry[i].clone() * pow_of_two::<F>(128)
                    - last_overflow.clone()
                    - b[i].clone()
                    - c[i].clone(),
            ));
        }
        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(2, operands.len());
    let a = split_u256_hi_lo(&operands[0]);
    let b = split_u256_hi_lo(&operands[1]);
    let (c, carry_hi) = operands[0].overflowing_sub(operands[1]);
    let (_, carry_lo) = a[1].overflowing_sub(b[1]);

    let c_u16s: Vec<u16> = c
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 * 256 + x[1] as u16)
        .collect();
    assert_eq!(16, c_u16s.len());
    let c_split = split_u256_hi_lo(&c);
    let row_0 = Row {
        tag: Tag::Sub,
        cnt: 0.into(),
        operand_0_hi: a[0],
        operand_0_lo: a[1],
        operand_1_hi: b[0],
        operand_1_lo: b[1],
        u16_0: c_u16s[8].into(),
        u16_1: c_u16s[9].into(),
        u16_2: c_u16s[10].into(),
        u16_3: c_u16s[11].into(),
        u16_4: c_u16s[12].into(),
        u16_5: c_u16s[13].into(),
        u16_6: c_u16s[14].into(),
        u16_7: c_u16s[15].into(),
    };
    let row_1 = Row {
        tag: Tag::Sub,
        cnt: 1.into(),
        operand_0_hi: c_split[0],
        operand_0_lo: c_split[1],
        operand_1_hi: (carry_hi as u8).into(),
        operand_1_lo: (carry_lo as u8).into(),
        u16_0: c_u16s[0].into(),
        u16_1: c_u16s[1].into(),
        u16_2: c_u16s[2].into(),
        u16_3: c_u16s[3].into(),
        u16_4: c_u16s[4].into(),
        u16_5: c_u16s[5].into(),
        u16_6: c_u16s[6].into(),
        u16_7: c_u16s[7].into(),
    };
    (vec![row_1, row_0], vec![c, (carry_hi as u8).into()])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(SubGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;
    #[test]
    fn test_gen_witness_sub() {
        let a = u128::MAX.into();
        let b = 3.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();
        assert_eq!(
            // a_lo + carrry_lo = b_lo + c_lo  a_hi + carry_hi << 128 - carry_lo= b_hi + c_hi
            arith[1].operand_0_lo + (arith[0].operand_1_lo << 128),
            arith[1].operand_1_lo + arith[0].operand_0_lo
        );
        println!(
            "{}",
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo
        );
        println!("{}", arith[1].operand_1_hi + arith[0].operand_0_hi);
        assert_eq!(
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo,
            arith[1].operand_1_hi + arith[0].operand_0_hi
        );
        assert_eq!(U256::from(0), result[1]);
    }
    #[test]
    fn test_gen_witness_lt() {
        let a = 3.into();
        let b = u128::MAX.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        println!(
            "{}",
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo
        );
        println!("{}", arith[1].operand_1_hi + arith[0].operand_0_hi);
        assert_eq!(
            // a_lo + carrry_lo = b_lo + c_lo  a_hi + carry_hi << 128 - carry_lo= b_hi + c_hi
            arith[1].operand_0_lo + (arith[0].operand_1_lo << 128),
            arith[1].operand_1_lo + arith[0].operand_0_lo
        );
        assert_eq!(
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo,
            arith[1].operand_1_hi + arith[0].operand_0_hi
        );
        assert_eq!(U256::from(1), result[1]);
    }
    #[test]
    fn test_gen_witness_gt() {
        let a = u128::MAX.into();
        let b = 3.into();
        let (arithmetic, result) = gen_witness(vec![b, a]);
        let arith = arithmetic.clone();
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();

        assert_eq!(
            // a_lo + carrry_lo = b_lo + c_lo  a_hi + carry_hi << 128 - carry_lo= b_hi + c_hi
            arith[1].operand_0_lo + (arith[0].operand_1_lo << 128),
            arith[1].operand_1_lo + arith[0].operand_0_lo
        );
        assert_eq!(
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo,
            arith[1].operand_1_hi + arith[0].operand_0_hi
        );
        assert_eq!(U256::from(1), result[1]);
        // test a == b
        let (arithmetic, result) = gen_witness(vec![b, b]);
        assert_eq!(
            // a_lo + carrry_lo = b_lo + c_lo  a_hi + carry_hi << 128 - carry_lo= b_hi + c_hi
            arith[1].operand_0_lo + (arith[0].operand_1_lo << 128),
            arith[1].operand_1_lo + arith[0].operand_0_lo
        );
        assert_eq!(
            arith[1].operand_0_hi + (arith[0].operand_1_hi << 128) - arith[0].operand_1_lo,
            arith[1].operand_1_hi + arith[0].operand_0_hi
        );
        assert_eq!(U256::from(0), result[1]);
    }
}
