// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{
    get_lt_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256};
use gadgets::simple_binary_number::SimpleBinaryNumber;
use gadgets::simple_lt::SimpleDiffGadget;
use gadgets::util::Expr;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// The function of the memory expansion circuit is to calculate whether to expand the memory given the offset_bound and memory_chunk_prev.
/// offset_bound represents the right interval of the memory segment access:
/// 1. The access length is fixed, such as the mload instruction, offset = 10, mload accesses length=32 at a time, then offset_bound = 42.
/// 2. There is also another situation where the memory is accessed with a given offset,
///    and the length is any value: when length is not 0, then offset_bound = offset + length.
///    When length = 0, offset_bound = 0, so no matter what value the offset takes, the memory will not expand.
pub(crate) struct MemoryExpansionGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for MemoryExpansionGadget<F> {
    fn name(&self) -> &'static str {
        "MEMORYEXPANSION"
    }

    fn tag(&self) -> Tag {
        Tag::MemoryExpansion
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
        let [offset_bound, memory_chunk_prev] = config.get_operand(0)(meta);
        let [expansion_tag, access_memory_size] = config.get_operand(1)(meta);
        let [remainder_0, _] = config.get_operand(2)(meta);

        let (_, offset_bound_u16s, access_memory_size_u16s) =
            get_u16s(config, meta, Rotation::cur());
        let (_, diff, _) = get_u16s(config, meta, Rotation::prev());
        let mut remainder_bits: Vec<_> = (4..8)
            .map(|i| config.get_u16(i, Rotation::prev())(meta))
            .collect();
        remainder_bits.insert(0, remainder_0);

        let mut constraints = vec![];

        // constraint offset_bound
        constraints.push((
            "offset_bound".to_string(),
            offset_bound.clone() - offset_bound_u16s.clone(),
        ));

        // constraint access_memory_size
        constraints.push((
            "access_memory_size".to_string(),
            access_memory_size.clone() - access_memory_size_u16s.clone(),
        ));

        let remainder_bits: [Expression<F>; 5] = remainder_bits.try_into().unwrap();
        let simple_binary_number = SimpleBinaryNumber::new(&remainder_bits);
        let remainder = simple_binary_number.value();

        constraints.extend(simple_binary_number.get_constraints());

        // constraint quotient * 32 + remainder = offset + 31
        constraints.push((
            "quotient * 32 + remainder = offset + 31".to_string(),
            access_memory_size.clone() * 32.expr() + remainder.clone()
                - offset_bound.clone()
                - 31.expr(),
        ));

        // constrain expansion_tag must be 0 or 1
        constraints.push((
            "expansion_tag must be 0 or 1".to_string(),
            expansion_tag.clone() * (expansion_tag.clone() - 1.expr()),
        ));

        // Constrain the size relationship between memory_chunk_prev and access_memory_size
        let is_expansion: SimpleDiffGadget<F, 8> = SimpleDiffGadget::new(
            &memory_chunk_prev,
            &access_memory_size,
            &expansion_tag,
            &diff,
        );
        constraints.extend(is_expansion.get_constraints());

        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
// witness rows(Tag::MemoryExpansion):
//
// +--------------+-------------------+---------------+--------------------+-----+--------------+--------------------+
// | operand0     | operand1          | operand2      | operand3           | cnt | u16s(0-3)    | u16s(4_7)          |
// +--------------+-------------------+---------------+--------------------+-----+--------------+--------------------+
// | r0           |                   |               |                    | 1   | diff         | r1|r2|r3|r4        |
// | offset_bound | memory_chunk_prev | expansion_tag | access_memory_size | 0   | offset_bound | access_memory_size |
// +--------------+-------------------+---------------+--------------------+-----+--------------+--------------------+
// Input: offset_bound, memory_chunk_prev
// The two input parameters above must be in the range of u64.
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    // Assert that the number of operands is 2
    assert_eq!(2, operands.len());

    let offset_bound = operands[0].as_u64();
    let memory_chunk_prev = operands[1].as_u64();
    let access_memory_size = (offset_bound + 31) / 32;
    let remainder = (offset_bound + 31) % 32;

    let mut offset_bound_u16s: Vec<u16> = offset_bound
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(4, offset_bound_u16s.len());

    let access_memory_size_u16s: Vec<u16> = access_memory_size
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let mut remainder_bits = [0; 5];
    let mut r = remainder as u16;
    for i in 0..5 {
        remainder_bits[4 - i] = r % 2;
        r /= 2;
    }

    let (expansion_tag, _, mut diff_u16s) = get_lt_operations(
        &memory_chunk_prev.into(),
        &access_memory_size.into(),
        &U256::from(2).pow(U256::from(64)),
    );

    offset_bound_u16s.extend(access_memory_size_u16s);
    let row0 = get_row(
        [offset_bound.into(), memory_chunk_prev.into()],
        [U256::from(expansion_tag as u8), access_memory_size.into()],
        offset_bound_u16s,
        0,
        Tag::MemoryExpansion,
    );

    let remainder_0 = U256::from(remainder_bits[0]);
    let _ = diff_u16s.split_off(4);
    diff_u16s.extend_from_slice(&remainder_bits[1..]);
    assert_eq!(8, diff_u16s.len());

    let row1 = get_row(
        [remainder_0, U256::zero()],
        [U256::zero(), U256::zero()],
        diff_u16s,
        1,
        Tag::MemoryExpansion,
    );

    (
        vec![row1, row0],
        vec![U256::from(expansion_tag as u8), access_memory_size.into()],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(MemoryExpansionGadget(PhantomData))
}

#[cfg(test)]
/// This module contains tests for the `gen_witness`, `get_lt_word_rows`, and `le_to_bytes` functions.
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    fn test_gen_witness_expansion() {
        let a = 1.into();
        let b = 100.into();

        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::zero());
        assert_eq!(result[1], U256::from(1)); // (1 + 31) / 32 = 1
    }

    #[test]
    fn test_gen_witness_expansion_1() {
        let a = 8.into();
        let b = 0.into();

        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::one());
        assert_eq!(result[1], U256::from(1)); // (8 + 31) / 32 = 1
    }

    #[test]
    fn test_gen_witness_no_expansion() {
        let a = 1234.into();
        let b = 2.into();

        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::one());
        assert_eq!(result[1], U256::from(39)); // (1234 + 31) /32= 39
    }
}
