use crate::arithmetic_circuit::operation::{get_row, OperationConfig, OperationGadget};
use crate::util::convert_u256_to_64_bytes;
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, ToLittleEndian, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, Expr};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::ops::Add;

pub(crate) struct U64OverflowGadget<F>(PhantomData<F>);

/// Used to determine whether there is a low 64-bit overflow for an operand of type U256.
/// Constraints:
///     `w = a_lo >> 64 + a_hi << 64`
///     `w * w_inv = 1 or 0`,
///     when w * w_inv = 1, represents U64 overflow, otherwise 0, represents no overflow.
impl<F: Field> OperationGadget<F> for U64OverflowGadget<F> {
    fn name(&self) -> &'static str {
        "U64Overflow"
    }

    fn tag(&self) -> Tag {
        Tag::U64Overflow
    }

    fn num_row(&self) -> usize {
        1
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (1, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        let a = config.get_operand(0)(meta);
        let w = config.get_operand(1)(meta);

        let a_lo_u16s = {
            let u16s: Vec<_> = (4..8)
                .map(|i| config.get_u16(i, Rotation::cur())(meta))
                .collect();
            expr_from_u16s(&u16s)
        };

        let w_is_zero = SimpleIsZero::new(&w[0], &w[1], String::from("w"));
        constraints.extend(w_is_zero.get_constraints());

        constraints.push((
            "w = a_lo >> 64 + a_hi << 64".to_string(),
            w[0].clone() - (a_lo_u16s + a[0].clone() * pow_of_two::<F>(64)),
        ));

        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness<F: Field>(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(1, operands.len());
    let a = split_u256_hi_lo(&operands[0]);

    let a_lo_u16s = a[1]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    // w = a_lo high 64 bit + a_hi * 2^64
    let w = (a[1] >> 64).add(a[0] << 64);

    let w_f = F::from_uniform_bytes(&convert_u256_to_64_bytes(&w));
    let w_inv = U256::from_little_endian(w_f.invert().unwrap_or(F::ZERO).to_repr().as_ref());

    let row_0 = get_row(a, [w, w_inv], a_lo_u16s, 0, Tag::U64Overflow);

    (vec![row_0], vec![w, w_inv])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(U64OverflowGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;
    use halo2_proofs::halo2curves::bn256::Fr;

    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let (arithmetic, result) = gen_witness::<Fr>(vec![a]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(U256::from(0), result[0]);
    }
}
