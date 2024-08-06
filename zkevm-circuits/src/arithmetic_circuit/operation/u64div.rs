// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{
    get_lt_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::util::Expr;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// formula: numerator / denominator = quotient (r) remainder.
/// numerator, denominator, quotient, remainder is u64 range.
/// denominator is usually a constant value, such as 32, 64, 512, etc.
pub(crate) struct MemoryExpansionGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for MemoryExpansionGadget<F> {
    fn name(&self) -> &'static str {
        "U64DIV"
    }

    fn tag(&self) -> Tag {
        Tag::U64Div
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
        // get operations
        let [numerator, denominator] = config.get_operand(0)(meta);
        let [quotient, remainder] = config.get_operand(1)(meta);
        let [lt, _] = config.get_operand(2)(meta);

        let (_, numerator_u16s, denominator_u16s) = get_u16s(config, meta, Rotation::cur());
        let (_, quotient_u16s, diff) = get_u16s(config, meta, Rotation::prev());

        let mut constraints = vec![];

        // constraint numerator
        constraints.push((
            "numerator u64 constraint".to_string(),
            numerator.clone() - numerator_u16s.clone(),
        ));

        // constraint denominator
        constraints.push((
            "denominator u64 constraint".to_string(),
            denominator.clone() - denominator_u16s.clone(),
        ));

        // constraint quotient
        constraints.push((
            "quotient u64 constraint".to_string(),
            quotient.clone() - quotient_u16s.clone(),
        ));

        // constraint quotient * denominator + remainder = numerator
        constraints.push((
            "quotient * denominator + remainder = numerator".to_string(),
            quotient.clone() * denominator.clone() + remainder.clone() - numerator.clone(),
        ));

        // constrain lt must be 0 or 1
        constraints.push((
            "lt must be 0 or 1".to_string(),
            lt.clone() * (lt.clone() - 1.expr()),
        ));

        // Constrain remainder < denominator
        let less: SimpleLtGadget<F, 8> =
            SimpleLtGadget::new(&remainder, &denominator, &1.expr(), &diff);
        constraints.extend(less.get_constraints());

        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
/// witness rows(Tag::U64Div):
/// +-----+------+-----+-----+-----+--------------+--------------+
/// | cnt |      |     |     |     |              |              |
/// +-----+------+-----+-----+-----+--------------+--------------+
/// | 1   | lt   |     |     |     | c_u16s(0..3) | diff(4..7)   |
/// | 0   | a    | b   | c   | d   | a_u16s(0..3) | b_u16s(4..7) |
/// +-----+------+-----+-----+-----+--------------+--------------+

pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    // Assert that the number of operands is 2
    assert_eq!(2, operands.len());

    let numerator = operands[0];
    let denominator = operands[1];

    let (quotient, remainder) = numerator.div_mod(denominator);
    assert!(remainder < denominator);

    let mut numerator_u16s: Vec<u16> = u64_to_u16s(numerator);
    assert_eq!(4, numerator_u16s.len());

    let mut denominator_u16s: Vec<u16> = u64_to_u16s(denominator);
    assert_eq!(4, denominator_u16s.len());

    let mut quotient_u16s: Vec<u16> = u64_to_u16s(quotient);
    assert_eq!(4, quotient_u16s.len());
    numerator_u16s.extend(denominator_u16s);

    let (lt, _, mut diff_u16s) =
        get_lt_operations(&remainder, &denominator, &U256::from(2).pow(U256::from(64)));

    let row0 = get_row(
        [numerator, denominator],
        [quotient, remainder],
        numerator_u16s,
        0,
        Tag::U64Div,
    );

    let _ = diff_u16s.split_off(4);
    quotient_u16s.extend(diff_u16s);

    let row1 = get_row(
        [(lt as u8).into(), U256::zero()],
        [U256::zero(); 2],
        quotient_u16s,
        1,
        Tag::U64Div,
    );

    (vec![row1, row0], vec![quotient, remainder])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(MemoryExpansionGadget(PhantomData))
}

fn u64_to_u16s(num: U256) -> Vec<u16> {
    num.as_u64()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect()
}

#[cfg(test)]
/// This module contains tests for the `gen_witness`, `get_lt_word_rows`, and `le_to_bytes` functions.
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    fn test_gen_witness_u64_div() {
        let a = 127.into();
        let b = 64.into();

        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::one());
        assert_eq!(result[1], U256::from(63));
    }
}
