// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{get_row, get_u16s, OperationConfig, OperationGadget};
use crate::util::convert_u256_to_64_bytes;
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, split_u256_hi_lo};
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
        (0, 0)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        let a = config.get_operand(0)(meta);
        let w = config.get_operand(1)(meta);

        // Get the high 64 bits of a_lo.
        let (a_lo_u16_sum, _, a_lo_u16_hi_sum) = get_u16s(config, meta, Rotation::cur());

        let w_is_zero = SimpleIsZero::new(&w[0], &w[1], String::from("w"));
        constraints.extend(w_is_zero.get_constraints());

        constraints.push((
            "w = a_lo >> 64 + a_hi << 64".to_string(),
            w[0].clone() - (a_lo_u16_hi_sum + a[0].clone() * pow_of_two::<F>(64)),
        ));
        constraints.push(("a_lo = u16 sum".to_string(), a[1].clone() - a_lo_u16_sum));

        constraints
    }
}

/// U64Overflow arithmetic witness rows. (Tag::U64Overflow)
/// +-----+---------+---------+---------+---------+-----------+
/// | cnt | op_0_hi | op_0_lo | op_1_hi | op_1_lo | u16s      |
/// +-----+---------+---------+---------+---------+-----------+
/// | 0   | a_hi    | a_lo    | w       | w_inv   | a_lo_u16s |
/// +-----+---------+---------+---------+---------+-----------+

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

    // a_lo_u16s is converted from a_lo (which is a 128-bit U256 type) to a vec<u16> vector
    // with a length of 16 in little-endian format. The elements from 0 to 8 represent the low 128 bits,
    // while the elements from 9 to 16 represent the high 128 bits, with all high bits being zero.
    // so, wo only need 0..8 elements.
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

    #[test]
    fn test_gen_witness_overflow() {
        let a = u128::MAX.into();
        let (arithmetic, result) = gen_witness::<Fr>(vec![a]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert!(result[0] > 0.into());
    }
}
