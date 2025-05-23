// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod operation;

use crate::arithmetic_circuit::operation::{get_every_operation_gadgets, OperationGadget};
use crate::table::ArithmeticTable;
use crate::util::{
    assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes, Challenges, SubCircuit,
    SubCircuitConfig,
};
use crate::witness::{arithmetic, Witness};
use arithmetic::{Row, Tag};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero::IsZeroInstruction;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Number needed for tag's BinaryNumberConfig, equals to log of number of tags
pub(crate) const LOG_NUM_ARITHMETIC_TAG: usize = 4;

/// Number of operands in one row
pub(crate) const NUM_OPERAND: usize = 2;

/// Number of u16 values in one row
const NUM_U16: usize = 8;

#[derive(Clone)]
pub struct ArithmeticCircuitConfig<F> {
    q_first_rows: Selector,
    q_enable: Selector,
    /// Tag for arithmetic operation type
    tag: BinaryNumberConfig<Tag, LOG_NUM_ARITHMETIC_TAG>,
    /// The operands in one row, split to 2 (high and low 128-bit)
    operands: [[Column<Advice>; 2]; NUM_OPERAND],
    /// The 16-bit values in one row
    u16s: [Column<Advice>; NUM_U16],
    /// Row counter, decremented for rows in one execution state
    cnt: Column<Advice>,
    /// IsZero chip for column cnt
    cnt_is_zero: IsZeroWithRotationConfig<F>,
}

impl<F: Field> ArithmeticCircuitConfig<F> {
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero);
        let tag = BinaryNumberChip::construct(self.tag);
        assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.cnt)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.operand_0_hi, self.operands[0][0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.operand_0_lo, self.operands[0][1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.operand_1_hi, self.operands[1][0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.operand_1_lo, self.operands[1][1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_0, self.u16s[0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_1, self.u16s[1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_2, self.u16s[2])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_3, self.u16s[3])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_4, self.u16s[4])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_5, self.u16s[5])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_6, self.u16s[6])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.u16_7, self.u16s[7])?;
        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt))),
        )?;
        tag.assign(region, offset, &row.tag)?;
        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // pad the first row. The helper row helps us define the first row cnt is 0
        // self.assign_row(region, 0, &Default::default())?;
        // assign the rows
        for (offset, row) in witness.arithmetic.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }

        // pad the rest rows
        for offset in witness.arithmetic.len()..num_row_incl_padding {
            self.assign_row(region, offset, &Default::default())?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "ARITHMETIC_cnt", self.cnt);
        self.tag
            .annotate_columns_in_region(region, "ARITHMETIC_tag");
        self.cnt_is_zero
            .annotate_columns_in_region(region, "ARITHMETIC_cnt_is_zero");
        for (index, value) in self.u16s.iter().enumerate() {
            region.name_column(|| format!("ARITHMETIC_u16_{}", index), *value);
        }
        for (index, value) in self.operands.iter().enumerate() {
            region.name_column(|| format!("ARITHMETIC_operand_{}_hi", index), value[0]);
            region.name_column(|| format!("ARITHMETIC_operand_{}_lo", index,), value[1]);
        }
    }
}

// Implement methods to get expression
impl<F: Field> ArithmeticCircuitConfig<F> {
    /// Get the operand, which could access other rotation
    pub(crate) fn get_operand(
        &self,
        index: usize,
    ) -> impl FnOnce(&mut VirtualCells<'_, F>) -> [Expression<F>; 2] {
        let rotation_index = -(index as isize / 2);
        let rotation = Rotation(rotation_index as i32);

        let index = index % NUM_OPERAND;
        let operands = self.operands[index];
        move |meta: &mut VirtualCells<'_, F>| {
            operands.map(|operand| meta.query_advice(operand, rotation))
        }
    }

    /// Get the u16 expression
    pub(crate) fn get_u16(
        &self,
        index: usize,
        rotation: Rotation,
    ) -> impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F> {
        assert!(index < NUM_U16);
        let column = self.u16s[index];
        move |meta: &mut VirtualCells<'_, F>| meta.query_advice(column, rotation)
    }
}

pub struct ArithmeticCircuitConfigArgs {
    pub(crate) q_enable: Selector,
    pub(crate) arithmetic_table: ArithmeticTable,
}

impl<F: Field> SubCircuitConfig<F> for ArithmeticCircuitConfig<F> {
    type ConfigArgs = ArithmeticCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            arithmetic_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let ArithmeticTable { tag, operands, cnt } = arithmetic_table;
        // init columns
        let u16s = std::array::from_fn(|_| meta.advice_column());
        let is_not_zero = Some(meta.advice_column());
        let cnt_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            cnt,
            is_not_zero,
        );
        let q_first_rows = meta.selector();
        let config = Self {
            q_first_rows,
            q_enable,
            tag,
            cnt,
            operands,
            u16s,
            cnt_is_zero,
        };
        // constraints
        meta.create_gate("ARITHMETIC_common_constraints", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_cur = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_next = meta.query_advice(config.cnt, Rotation::next());
            let tag_cur = config.tag.value(Rotation::cur())(meta);
            let tag_next = config.tag.value(Rotation::next())(meta);
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let condition = q_enable * (1.expr() - cnt_is_zero);
            vec![
                (
                    "cnt decreases if cnt!=0",
                    condition.clone() * (cnt_cur - cnt_next - 1.expr()),
                ),
                ("tag is same if cnt!=0", condition * (tag_cur - tag_next)),
            ]
        });
        let gadgets: Vec<Box<dyn OperationGadget<F>>> = get_every_operation_gadgets!();
        for gadget in &gadgets {
            // the constraints that all execution state requires, e.g., cnt=num_row-1 at the first row
            meta.create_gate(format!("ARITHMETIC_OPERATION_{}", gadget.name()), |meta| {
                let q_enable = meta.query_selector(config.q_enable);
                let num_row = gadget.num_row();
                let cnt_prev_state = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32));
                // cnt in first row of this state
                let cnt_first = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32 + 1));
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let tag_value_equals = config.tag.value_equals(gadget.tag(), Rotation::cur())(meta);
                let condition = q_enable * cnt_is_zero * tag_value_equals;
                vec![
                    (
                        "prev state last cnt = 0",
                        condition.clone() * cnt_prev_state,
                    ),
                    (
                        "this state first cnt is const",
                        condition.clone() * (cnt_first - (num_row - 1).expr()),
                    ),
                ]
            });
            // the constraints for the specific execution state, extracted from the gadget
            meta.create_gate(
                format!("ARITHMETIC_OPERATION_GADGET_{}", gadget.name()),
                |meta| {
                    // constraints without condition
                    let constraints = gadget.get_constraints(&config, meta);
                    if constraints.is_empty() {
                        return vec![("placeholder due to no constraint".into(), 0.expr())];
                    }
                    let q_enable = meta.query_selector(config.q_enable);
                    let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                    let tag_value_equals =
                        config.tag.value_equals(gadget.tag(), Rotation::cur())(meta);
                    let condition = q_enable * cnt_is_zero * tag_value_equals;
                    constraints
                        .into_iter()
                        .map(|(s, e)| (s, condition.clone() * e))
                        .collect::<Vec<(String, Expression<F>)>>()
                },
            );
        }

        meta.create_gate("ARITHMETIC_q_first_rows_constrains", |meta| {
            let q_first_rows = meta.query_selector(config.q_first_rows);
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let tag = config.tag.value(Rotation::cur())(meta);
            let operands_0_hi = meta.query_advice(config.operands[0][0], Rotation::cur());
            let operands_0_lo = meta.query_advice(config.operands[0][1], Rotation::cur());
            let operands_1_hi = meta.query_advice(config.operands[1][0], Rotation::cur());
            let operands_1_lo = meta.query_advice(config.operands[1][1], Rotation::cur());
            let u16_0 = meta.query_advice(config.u16s[0], Rotation::cur());
            let u16_1 = meta.query_advice(config.u16s[1], Rotation::cur());
            let u16_2 = meta.query_advice(config.u16s[2], Rotation::cur());
            let u16_3 = meta.query_advice(config.u16s[3], Rotation::cur());
            let u16_4 = meta.query_advice(config.u16s[4], Rotation::cur());
            let u16_5 = meta.query_advice(config.u16s[5], Rotation::cur());
            let u16_6 = meta.query_advice(config.u16s[6], Rotation::cur());
            let u16_7 = meta.query_advice(config.u16s[7], Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());

            vec![
                ("q_first_rows=1 ==> tag=0", q_first_rows.clone() * tag),
                (
                    "q_first_rows=1 ==> operands_0_hi=0",
                    q_first_rows.clone() * operands_0_hi,
                ),
                (
                    "q_first_rows=1 ==> operands_0_lo=0",
                    q_first_rows.clone() * operands_0_lo,
                ),
                (
                    "q_first_rows=1 ==> operands_1_hi=0",
                    q_first_rows.clone() * operands_1_hi,
                ),
                (
                    "q_first_rows=1 ==> operands_1_lo=0",
                    q_first_rows.clone() * operands_1_lo,
                ),
                ("q_first_rows=1 ==> u16_0=0", q_first_rows.clone() * u16_0),
                ("q_first_rows=1 ==> u16_1=0", q_first_rows.clone() * u16_1),
                ("q_first_rows=1 ==> u16_2=0", q_first_rows.clone() * u16_2),
                ("q_first_rows=1 ==> u16_3=0", q_first_rows.clone() * u16_3),
                ("q_first_rows=1 ==> u16_4=0", q_first_rows.clone() * u16_4),
                ("q_first_rows=1 ==> u16_5=0", q_first_rows.clone() * u16_5),
                ("q_first_rows=1 ==> u16_6=0", q_first_rows.clone() * u16_6),
                ("q_first_rows=1 ==> u16_7=0", q_first_rows.clone() * u16_7),
                ("q_first_rows=1 ==> cnt=0", q_first_rows.clone() * cnt),
                (
                    "q_first_rows=1 ==> cnt_is_zero=1",
                    q_first_rows.clone() * (1.expr() - cnt_is_zero),
                ),
            ]
        });

        config
    }
}

#[derive(Clone, Default, Debug)]
pub struct ArithmeticCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for ArithmeticCircuit<F, MAX_NUM_ROW> {
    type Config = ArithmeticCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        ArithmeticCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "arithmetic circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;

                // enable q_first_rows
                for offset in 0..Self::unusable_rows().0 {
                    config.q_first_rows.enable(&mut region, offset)?;
                }

                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        let gadgets: Vec<Box<dyn OperationGadget<F>>> = get_every_operation_gadgets!();
        let unusable_begin =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().0)).unwrap();
        let unusable_end =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().1)).unwrap();
        (unusable_begin, unusable_end)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.arithmetic.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::log2_ceil;
    use eth_types::U256;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    const TEST_SIZE: usize = 200;

    #[derive(Clone)]
    pub struct ArithmeticTestCircuitConfig<F: Field> {
        pub arithmetic_circuit: ArithmeticCircuitConfig<F>,
        pub challenges: Challenges,
    }

    impl<F: Field> SubCircuitConfig<F> for ArithmeticTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            let q_enable = meta.complex_selector();
            let arithmetic_table = ArithmeticTable::construct(meta, q_enable);
            let challenges = Challenges::construct(meta);
            ArithmeticTestCircuitConfig {
                arithmetic_circuit: ArithmeticCircuitConfig::new(
                    meta,
                    ArithmeticCircuitConfigArgs {
                        q_enable,
                        arithmetic_table,
                    },
                ),
                challenges,
            }
        }
    }

    #[derive(Clone, Default, Debug)]
    pub struct ArithmeticTestCircuit<F: Field>(ArithmeticCircuit<F, TEST_SIZE>);

    impl<F: Field> Circuit<F> for ArithmeticTestCircuit<F> {
        type Config = ArithmeticTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config::new(meta, ())
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.0
                .synthesize_sub(&config.arithmetic_circuit, &mut layouter, &challenges)
        }
    }

    impl<F: Field> ArithmeticTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            let mut arithmetic = Vec::new();
            let num_padding_begin = unusable_rows::<F>().0;
            for _ in 0..num_padding_begin {
                arithmetic.push(Default::default());
            }
            arithmetic.extend(witness.arithmetic.clone());
            let witness = Witness {
                arithmetic,
                ..Default::default()
            };
            Self(ArithmeticCircuit::new_from_witness(&witness))
        }
    }

    fn unusable_rows<F: Field>() -> (usize, usize) {
        let gadgets: Vec<Box<dyn OperationGadget<F>>> = get_every_operation_gadgets!();
        let usable_max =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().0)).unwrap();
        let unusable_end =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().1)).unwrap();
        (usable_max, unusable_end)
    }

    #[test]
    fn test_add_witness() {
        let (arithmetic, result) =
            operation::add::gen_witness(vec![388822.into(), u128::MAX.into()]);

        // there is carry for low 128-bit
        assert_eq!(result[1], 1.into());
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_add_mod_witness() {
        let (arithmetic_1, result_1) =
            self::operation::addmod::gen_witness(vec![3.into(), 4.into(), 2.into()]);
        assert_eq!(result_1[0], 1.into());

        let (arithmetic_2, result_2) =
            self::operation::addmod::gen_witness(vec![4.into(), 5.into(), 0.into()]);
        assert_eq!(result_2[0], 0.into());

        let (arithmetic_3, result_3) =
            self::operation::addmod::gen_witness(vec![U256::MAX, U256::MAX, 3.into()]);
        assert_eq!(result_3[0], 0.into());

        let (arithmetic_4, result_4) =
            self::operation::addmod::gen_witness(vec![0.into(), 0.into(), 0.into()]);
        assert_eq!(result_4[0], 0.into());

        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic_1);
        arithmetic.extend(arithmetic_2);
        arithmetic.extend(arithmetic_3);
        arithmetic.extend(arithmetic_4);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sub_gt_witness() {
        let (arithmetic, result) = operation::sub::gen_witness(vec![128.into(), u128::MAX.into()]);

        // there is no carry, so it is 0
        assert_eq!(result[1], (U256::from(1) << 128) + 1);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_lt_witness() {
        let (arithmetic, result) = operation::sub::gen_witness(vec![u128::MAX.into(), U256::MAX]);

        // there is carry for high 128-bit, so it is 1<<128
        assert_eq!(result[1], U256::from(1) << 128);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_mul_witness() {
        let (arithmetic, _result) = operation::mul::gen_witness(vec![u128::MAX.into(), U256::MAX]);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_div_mod_witness() {
        let (arithmetic1, result1) =
            self::operation::div_mod::gen_witness(vec![u128::MAX.into(), U256::MAX]);
        assert_eq!(result1[0], u128::MAX.into());
        assert_eq!(result1[1], 0.into());

        let (arithmetic2, result2) =
            self::operation::div_mod::gen_witness(vec![U256::MAX, u128::MAX.into()]);
        assert_eq!(result2[0], 0.into());
        assert_eq!(result2[1] >> 128, 1.into());
        assert_eq!(result2[1].low_u128(), 1 as u128);

        let (arithmetic3, result3) =
            self::operation::div_mod::gen_witness(vec![0.into(), u128::MAX.into()]);
        assert_eq!(result3[0], 0.into());
        assert_eq!(result3[1], 0.into());

        let (arithmetic4, result4) =
            self::operation::div_mod::gen_witness(vec![U256::MAX, 0.into()]);
        assert_eq!(result4[0], 0.into());
        assert_eq!(result4[1], 0.into());

        let (arithmetic5, result5) =
            self::operation::div_mod::gen_witness(vec![0.into(), 0.into()]);
        assert_eq!(result5[0], 0.into());
        assert_eq!(result5[1], 0.into());

        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic1);
        arithmetic.extend(arithmetic2);
        arithmetic.extend(arithmetic3);
        arithmetic.extend(arithmetic4);
        arithmetic.extend(arithmetic5);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_slt_sgt_witness() {
        let (arithmetic1, _result) = self::operation::slt_sgt::gen_witness(vec![
            U256::from(u128::MAX) + U256::from(59509090),
            U256::from(u128::MAX) + U256::from(56789),
        ]);
        let (arithmetic2, _result2) = operation::slt_sgt::gen_witness(vec![
            U256::MAX - U256::from(59509090),
            U256::MAX - U256::from(590),
        ]);
        let (arithmetic3, _result3) =
            operation::slt_sgt::gen_witness(vec![u128::MAX.into(), U256::MAX - U256::from(3434)]);

        // there is a = 0
        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic1);
        arithmetic.extend(arithmetic2);
        arithmetic.extend(arithmetic3);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sdiv_smod_witness() {
        let (arithmetic1, _result) =
            self::operation::sdiv_smod::gen_witness(vec![u128::MAX.into(), U256::MAX]);
        let (arithmetic2, _result2) = self::operation::sdiv_smod::gen_witness(vec![
            U256::MAX,
            U256::from(u128::MAX) + U256::from(4567890),
        ]);
        let (arithmetic3, _result3) =
            self::operation::sdiv_smod::gen_witness(vec![0.into(), u128::MAX.into()]);
        let (arithmetic4, _result4) =
            self::operation::sdiv_smod::gen_witness(vec![U256::MAX, 0.into()]);
        let (arithmetic5, _result5) = self::operation::sdiv_smod::gen_witness(vec![
            U256::MAX - U256::from(47890),
            U256::MAX - U256::from(70),
        ]);
        let (arithmetic6, _result6) =
            self::operation::sdiv_smod::gen_witness(vec![u128::MAX.into(), 45678990.into()]);

        // there is a = 0
        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic1);
        arithmetic.extend(arithmetic2);
        arithmetic.extend(arithmetic3);
        arithmetic.extend(arithmetic4);
        arithmetic.extend(arithmetic5);
        arithmetic.extend(arithmetic6);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness);
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_mulmod_witness() {
        let (arithmetic1, _) = operation::mulmod::gen_witness(vec![4.into(), 7.into(), 5.into()]);
        let (arithmetic2, _result2) = operation::mulmod::gen_witness(vec![
            U256::MAX - U256::from(59509090),
            U256::MAX - U256::from(590),
            U256::MAX,
        ]);
        let (arithmetic3, _) = operation::mulmod::gen_witness(vec![
            u128::MAX.into(),
            U256::MAX - U256::from(3434),
            255.into(),
        ]);
        let (arithmetic4, _) = operation::mulmod::gen_witness(vec![
            u128::MAX.into(),
            U256::MAX - U256::from(434),
            0.into(),
        ]);
        let (arithmetic5, _) =
            operation::mulmod::gen_witness(vec![U256::MAX, U256::MAX, 12.into()]);

        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic1);
        arithmetic.extend(arithmetic2);
        arithmetic.extend(arithmetic3);
        arithmetic.extend(arithmetic4);
        arithmetic.extend(arithmetic5);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness.clone());
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_u64overflow_witness() {
        let (arithmetic1, _result) = operation::u64overflow::gen_witness::<Fr>(vec![0xfa.into()]);
        let (arithmetic2, _result2) =
            operation::u64overflow::gen_witness::<Fr>(vec![u128::MAX.into()]);

        let mut arithmetic = Vec::new();
        arithmetic.extend(arithmetic1);
        arithmetic.extend(arithmetic2);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        let circuit = ArithmeticTestCircuit::new(witness.clone());
        let k = log2_ceil(TEST_SIZE);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        witness.print_csv();
        prover.assert_satisfied();
    }
}
