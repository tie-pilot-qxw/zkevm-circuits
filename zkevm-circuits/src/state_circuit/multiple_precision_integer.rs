// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::usize;

use crate::state_circuit::ordering::{CALLID_OR_ADDRESS_LIMBS, POINTER_LIMBS, STAMP_LIMBS};
use crate::table::FixedTable;
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::Error;
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;

/// Compute the little-endian representation of a data structure.
/// N is the number of u16 required in little endian order.
/// 将元素拆分为limbs数组进行标识
/// |limb0 | limb1 | limb2 | limb3 | ....
pub trait Tolimbs<const N: usize> {
    fn to_limbs(&self) -> [u16; N];
}

// 将call_id_contract_addr 拆分为10个limb表达
impl Tolimbs<CALLID_OR_ADDRESS_LIMBS> for U256 {
    fn to_limbs(&self) -> [u16; CALLID_OR_ADDRESS_LIMBS] {
        to_limbs_for_u256(self)
    }
}

// 将pointer_lo/hi 拆分为8个limb表达
impl Tolimbs<POINTER_LIMBS> for U256 {
    fn to_limbs(&self) -> [u16; POINTER_LIMBS] {
        to_limbs_for_u256(self)
    }
}

// Gets the little-endian of U256, taking the first N elements in byte order.
fn to_limbs_for_u256<T: ToLittleEndian, const N: usize>(val: &T) -> [u16; N] {
    le_bytes_to_limbs(&val.to_le_bytes())[..N]
        .try_into()
        .unwrap()
}

// 将stamp拆分为2个limb表达
impl Tolimbs<STAMP_LIMBS> for u32 {
    fn to_limbs(&self) -> [u16; STAMP_LIMBS] {
        le_bytes_to_limbs(&self.to_le_bytes()).try_into().unwrap()
    }
}

/// Assign the value represented in little-endian order of data
/// type T to the corresponding Column.
#[derive(Clone, Copy, Debug)]
pub struct Config<T, const N: usize>
where
    T: Tolimbs<N>,
{
    pub limbs: [Column<Advice>; N],
    _marker: PhantomData<T>,
}

// 将val拆分为limbs，对分配的limbs Advice进行赋值
// 如 stamp 拆分两个limb，同时申请了两个Advice列
// 将拆分的两个limb 赋值到两个Advice列中，offset为对应列的行
fn assign_for_config<T: Tolimbs<N>, F: Field, const N: usize>(
    region: &mut Region<'_, F>,
    config: &Config<T, N>,
    val: T,
    offset: usize,
) -> Result<(), Error> {
    let limbs: [u16; N] = val.to_limbs();
    for (i, &limb) in limbs.iter().enumerate() {
        region.assign_advice(
            || format!("limb[{i}] in u32 mpi"),
            config.limbs[i],
            offset,
            || Value::known(F::from(limb as u64)),
        )?;
    }
    Ok(())
}

// 对limbs Advice进行注释的实现
fn annotate_columns_in_region<T: Tolimbs<N>, F: Field, const N: usize>(
    region: &mut Region<'_, F>,
    config: &Config<T, N>,
    prefix: &str,
) {
    let mut annotations = Vec::new();
    for (i, _) in config.limbs.iter().enumerate() {
        annotations.push(format!("MPI_limbs_{i}"));
    }
    config
        .limbs
        .iter()
        .zip(annotations.iter())
        .for_each(|(col, ann)| region.name_column(|| format!("{prefix}_{ann}"), *col))
}

// 将pointer_lo/hi赋值给拆分的limbs Advice列，并对limbs Advice列进行注释
impl Config<U256, POINTER_LIMBS> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: U256,
    ) -> Result<(), Error> {
        assign_for_config(region, self, value, offset)
    }

    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        annotate_columns_in_region(region, self, prefix)
    }
}

// 将stamp赋值给拆分的limbs Advice列，并对limbs Advice列进行注释
impl Config<u32, STAMP_LIMBS> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u32,
    ) -> Result<(), Error> {
        assign_for_config(region, self, value, offset)
    }

    pub fn annotate_colums_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        annotate_columns_in_region(region, self, prefix)
    }
}

// 将call_id_contract_addr赋值给拆分的limbs Advice列，并对limbs Advice列进行注释
impl Config<U256, CALLID_OR_ADDRESS_LIMBS> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: U256,
    ) -> Result<(), Error> {
        assign_for_config(region, self, value, offset)
    }

    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        annotate_columns_in_region(region, self, prefix)
    }
}

/// Create the Columns required by the Config<T,N> structure and
/// add corresponding constraints to these Columns
pub struct Chip<F: Field, T, const N: usize>
where
    T: Tolimbs<N>,
{
    config: Config<T, N>,
    _marker: PhantomData<F>,
}

impl<F: Field, T, const N: usize> Chip<F, T, N>
where
    T: Tolimbs<N>,
{
    pub fn construct(config: Config<T, N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // 生成limbs 对应的Advice列，并为Advice列填充约束
    // 1. 约束limb Advice的值在u16范围
    // 2. 约束limbs的值等于被拆分的value
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        value: Column<Advice>,
        fixed_table: FixedTable,
    ) -> Config<T, N> {
        let limbs = [0; N].map(|_| meta.advice_column());

        // 约束所有limb填充的值必须为16 bit范围
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        for limb in limbs {
            use crate::table::LookupEntry;
            meta.lookup_any("mpi limb fits into u16", |meta| {
                let entry = LookupEntry::U16(meta.query_advice(limb, Rotation::cur()));
                let lookup_vec = fixed_table.get_lookup_vector(meta, entry);
                lookup_vec
                    .into_iter()
                    .map(|(left, right)| {
                        let selector: Expression<F> = meta.query_selector(selector);
                        (selector * left, right)
                    })
                    .collect()
            });
        }
        // Constrains the little-endian result represented by limbs to be equal to value<T>
        // 约束limbs组合的值等于value，标识limbs确实是由value拆分得来。
        meta.create_gate("mpi value matches claimed limbs", |meta| {
            let selector: Expression<F> = meta.query_selector(selector);
            let value: Expression<F> = meta.query_advice(value, Rotation::cur());
            let limbs = limbs.map(|limb| meta.query_advice(limb, Rotation::cur()));
            vec![selector * (value - value_from_limbs(&limbs))]
        });
        Config {
            limbs,
            _marker: PhantomData,
        }
    }
    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

/// Convert the bytes of little-endian to limbs
fn le_bytes_to_limbs(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .tuples()
        .map(|(lo, hi)| u16::from_le_bytes([*lo, *hi]))
        .collect()
}

/// The little-endian order of the limb is converted to a big-endian order expression
fn value_from_limbs<F: Field>(limbs: &[Expression<F>]) -> Expression<F> {
    limbs.iter().rev().fold(0u64.expr(), |result, limb| {
        limb.clone() + result * (1u64 << 16).expr()
    })
}

#[cfg(test)]
mod test {
    use super::Tolimbs;
    use super::{CALLID_OR_ADDRESS_LIMBS, POINTER_LIMBS};
    use eth_types::U256;

    #[test]
    pub fn test_to_limbs_u32() {
        // little-endian
        let biga = U256::from(10);
        let a: [u16; POINTER_LIMBS] = biga.to_limbs();
        assert_eq!([10, 0, 0, 0, 0, 0, 0, 0], a);

        let a: [u16; CALLID_OR_ADDRESS_LIMBS] = biga.to_limbs();
        assert_eq!([10, 0, 0, 0, 0, 0, 0, 0, 0, 0], a);

        let val = 10u32;
        let a = val.to_limbs();
        assert_eq!([10, 0], a);
    }
}
