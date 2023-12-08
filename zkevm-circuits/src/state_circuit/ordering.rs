use crate::state_circuit::{lookups, SortedElements};
use crate::witness::state;
use eth_types::{Field, ToBigEndian};
use itertools::Itertools;
use std::iter::once;
use strum::IntoEnumIterator;

use gadgets::{
    binary_number_with_real_selector::{AsBits, BinaryNumberChip, BinaryNumberConfig},
    util::Expr,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use strum_macros::EnumIter;

pub const POINTER_LIMBS: usize = 8;
pub const STAMP_LIMBS: usize = 2;
pub const CALLID_OR_ADDRESS_LIMBS: usize = 10;
/// 512bit. every element is 16bit. so have number of 32 elements;
/// 1 + 10 + 8 + 8 + 2 = 22 * 16 = 352 bit
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LimbIndex {
    Tag,
    CallIdOrAddress9,
    CallIdOrAddress8,
    CallIdOrAddress7,
    CallIdOrAddress6,
    CallIdOrAddress5,
    CallIdOrAddress4,
    CallIdOrAddress3,
    CallIdOrAddress2,
    CallIdOrAddress1,
    CallIdOrAddress0,
    PointerHi7,
    PointerHi6,
    PointerHi5,
    PointerHi4,
    PointerHi3,
    PointerHi2,
    PointerHi1,
    PointerHi0,
    PointerLo7,
    PointerLo6,
    PointerLo5,
    PointerLo4,
    PointerLo3,
    PointerLo2,
    PointerLo1,
    PointerLo0,
    Stamp1,
    Stamp0,
}

impl AsBits<5> for LimbIndex {
    fn as_bits(&self) -> [bool; 5] {
        let mut bits = [false; 5];
        let mut x = *self as u8;
        for i in 0..5 {
            bits[4 - i] = x % 2 == 1;
            x /= 2;
        }
        assert_eq!(x, 0);
        bits
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub(crate) selector: Selector,
    // tag: Tag,
    pub first_different_limb: BinaryNumberConfig<LimbIndex, 5>,
    pub limb_difference: Column<Advice>,
    pub limb_difference_inverse: Column<Advice>,
}

impl Config {
    pub fn new<F: Field>(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        keys: SortedElements,
        lookup: lookups::Config,
    ) -> Self {
        let first_different_limb = BinaryNumberChip::configure(meta, selector, None);
        let limb_difference = meta.advice_column();
        let limb_difference_inverse = meta.advice_column();

        let config = Config {
            selector,
            first_different_limb,
            limb_difference,
            limb_difference_inverse,
        };

        lookup.range_check_u16(meta, "limb_difference fits into u16", |meta| {
            meta.query_advice(limb_difference, Rotation::cur())
        });

        meta.create_gate("limb_difference is not zero", |meta| {
            let selector = meta.query_selector(selector);
            let limb_difference = meta.query_advice(limb_difference, Rotation::cur());
            let limb_difference_inverse =
                meta.query_advice(limb_difference_inverse, Rotation::cur());
            let tag = keys
                .tag
                .value_equals(state::Tag::EndPadding, Rotation::cur())(meta);
            // limb_difference with the offset = cur-prev
            // when tag is EndPadding on the cur, the value = EndPadding - prev(tag),
            // should not enable constraint in the cur.
            vec![
                selector
                    * (1.expr() - limb_difference * limb_difference_inverse)
                    * (1.expr() - tag),
            ]
        });

        meta.create_gate(
            "limb difference before first_different_limb are all 0",
            |meta| {
                let selector = meta.query_selector(selector);
                let cur = Queries::new(meta, keys, Rotation::cur());
                let prev = Queries::new(meta, keys, Rotation::prev());
                let tag = keys
                    .tag
                    .value_equals(state::Tag::EndPadding, Rotation::cur())(
                    meta
                );
                let mut constraints = vec![];
                for (i, rlc_expression) in LimbIndex::iter().zip(square_limb_differences(cur, prev))
                {
                    constraints.push(
                        selector.clone()
                            * first_different_limb.value_equals(i, Rotation::cur())(meta)
                            * rlc_expression
                            * (1.expr() - tag.clone()),
                    )
                }
                constraints
            },
        );

        meta.create_gate("limb_difference equals of limbs at index", |meta| {
            let mut constraints = vec![];
            let selector = meta.query_selector(selector);
            let cur: Queries<F> = Queries::new(meta, keys, Rotation::cur());
            let prev = Queries::new(meta, keys, Rotation::prev());
            let limb_difference = meta.query_advice(limb_difference, Rotation::cur());
            let tag = keys
                .tag
                .value_equals(state::Tag::EndPadding, Rotation::cur())(meta);

            for ((i, cur_limb), prev_limb) in
                LimbIndex::iter().zip(cur.be_limbs()).zip(prev.be_limbs())
            {
                constraints.push(
                    selector.clone()
                        * first_different_limb.value_equals(i, Rotation::cur())(meta)
                        * (limb_difference.clone() - cur_limb + prev_limb)
                        * (1.expr() - tag.clone()),
                )
            }

            constraints
        });
        config
    }

    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: &state::Row,
        prev: &state::Row,
    ) -> Result<LimbIndex, Error> {
        let cur_be_limbs = state_to_be_limbs(cur);
        let prev_be_limbs = state_to_be_limbs(prev);

        let find_result = LimbIndex::iter()
            .zip(cur_be_limbs)
            .zip(prev_be_limbs)
            .find(|((_, a), b)| a != b);
        let ((index, cur_limb), prev_limb) = if cfg!(test) {
            find_result.unwrap_or(((LimbIndex::Stamp0, 0u16), 0u16))
        } else {
            find_result.expect("repeated state row stamp")
        };

        BinaryNumberChip::construct(self.first_different_limb).assign(region, offset, &index)?;
        let limb_difference = F::from(cur_limb as u64) - F::from(prev_limb as u64);
        region.assign_advice(
            || "limb_difference",
            self.limb_difference,
            offset,
            || Value::known(limb_difference),
        )?;
        region.assign_advice(
            || "limb_difference_inverse",
            self.limb_difference_inverse,
            offset,
            || Value::known(limb_difference.invert().unwrap()),
        )?;

        Ok(index)
    }

    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        [
            (self.limb_difference, "limb_difference"),
            (self.limb_difference_inverse, "limb_difference_inverse"),
        ]
        .iter()
        .for_each(|(col, ann)| region.name_column(|| format!("{prefix}_{ann}"), *col));
        self.first_different_limb
            .annotate_columns_in_region(region, prefix);
    }
}

pub struct Queries<F: Field> {
    tag: Expression<F>,
    call_id_or_address: [Expression<F>; CALLID_OR_ADDRESS_LIMBS],
    pointer_hi: [Expression<F>; POINTER_LIMBS],
    pointer_lo: [Expression<F>; POINTER_LIMBS],
    stamp: [Expression<F>; STAMP_LIMBS],
}

impl<F: Field> Queries<F> {
    fn new(meta: &mut VirtualCells<'_, F>, keys: SortedElements, ratation: Rotation) -> Self {
        let tag = keys.tag.value(ratation)(meta);
        let mut query_advice = |column| meta.query_advice(column, ratation);
        Self {
            tag: tag,
            call_id_or_address: keys.call_id_or_address.limbs.map(&mut query_advice),
            pointer_hi: keys.pointer_hi.limbs.map(&mut query_advice),
            pointer_lo: keys.pointer_lo.limbs.map(&mut query_advice),
            stamp: keys.stamp.limbs.map(&mut query_advice),
        }
    }

    fn be_limbs(&self) -> Vec<Expression<F>> {
        once(&self.tag)
            .chain(self.call_id_or_address.iter().rev())
            .chain(self.pointer_hi.iter().rev())
            .chain(self.pointer_lo.iter().rev())
            .chain(self.stamp.iter().rev())
            .cloned()
            .collect()
    }
}

fn square_limb_differences<F: Field>(cur: Queries<F>, prev: Queries<F>) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs().iter().zip(&prev.be_limbs()) {
        result.push(partial_sum.clone());
        // pseudo code：diff = cur_limb - prev_limb
        // partial_sum += diff
        // result = Vec[partial_sum...]
        partial_sum = partial_sum
            + (cur_limb.clone() - prev_limb.clone()) * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

fn state_to_be_limbs(row: &state::Row) -> Vec<u16> {
    let mut be_bytes = vec![0u8];
    be_bytes.push(row.tag.unwrap() as u8);
    be_bytes.extend_from_slice(&row.call_id_contract_addr.unwrap_or_default().to_be_bytes()[12..]); // 160bit = 20 byte
    be_bytes.extend_from_slice(&row.pointer_hi.unwrap_or_default().to_be_bytes()[16..]); //128bit = 16 byte
    be_bytes.extend_from_slice(&row.pointer_lo.unwrap_or_default().to_be_bytes()[16..]);
    be_bytes.extend_from_slice(&row.stamp.unwrap_or_default().to_be_bytes()[28..]);

    be_bytes
        .iter()
        .tuples()
        .map(|(hi, lo)| u16::from_be_bytes([*hi, *lo]))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::witness::state;

    use super::state_to_be_limbs;
    #[test]
    fn test_state_to_be_limbs() {
        let row1 = state::Row {
            tag: Some(state::Tag::Stack),
            call_id_contract_addr: Some(1000.into()),
            pointer_hi: Some(90.into()),
            pointer_lo: Some(9.into()),
            stamp: Some(10.into()),
            ..Default::default()
        };

        let limbs = state_to_be_limbs(&row1);
        println!("state to limbs of u16: {:?}", limbs);
    }
}
