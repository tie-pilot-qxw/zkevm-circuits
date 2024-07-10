use crate::constant::LOG_NUM_EXP_TAG;
use crate::table::{ArithmeticTable, ExpTable, LookupEntry};
use crate::util::{
    assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes, Challenges, SubCircuit,
    SubCircuitConfig,
};
use crate::witness::exp::{Row, Tag};
use crate::witness::{arithmetic, Witness};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) const EXP_NUM_OPERAND: usize = 2;

const V_128: u64 = 128;

#[derive(Clone)]
pub struct ExpCircuitConfig<F: Field> {
    q_enable: Selector,
    /// the operation tag, zero,one,bit,square
    pub tag: BinaryNumberConfig<Tag, LOG_NUM_EXP_TAG>,
    /// base hi , base lo
    pub base: [Column<Advice>; EXP_NUM_OPERAND],
    /// index hi, index lo
    pub index: [Column<Advice>; EXP_NUM_OPERAND],
    /// power hi, power lo
    pub power: [Column<Advice>; EXP_NUM_OPERAND],
    /// count
    pub count: Column<Advice>,
    /// is_high
    // pub is_high: Column<Advice>,
    /// IsZero chip for column count
    pub count_is_zero: IsZeroWithRotationConfig<F>,
    /// for chip to determine whether count is 128
    pub count_is_128: IsZeroConfig<F>,
    /// arithmetic table for lookup
    arithmetic_table: ArithmeticTable,
}

pub struct ExpCircuitConfigArgs {
    pub arithmetic_table: ArithmeticTable,
    pub exp_table: ExpTable,
}

impl<F: Field> SubCircuitConfig<F> for ExpCircuitConfig<F> {
    type ConfigArgs = ExpCircuitConfigArgs;
    /// Constructor
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            arithmetic_table,
            exp_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let ExpTable { base, index, power } = exp_table;
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let count = meta.advice_column();
        // let is_high = meta.advice_column();
        let count_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            count,
            None,
        );

        let _count_minus_128_inv = meta.advice_column();
        let count_is_128 = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let count = meta.query_advice(count, Rotation::cur());
                count - V_128.expr()
            },
            _count_minus_128_inv,
        );

        let config = Self {
            q_enable,
            tag,
            base,
            index,
            power,
            count,
            // is_high,
            count_is_zero,
            count_is_128,
            arithmetic_table,
        };

        // constrain base
        // if TAG is ONE,SQUARE,BIT,then base hi/lo = base hi/lo
        meta.create_gate("EXP_BASE", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let tag_is_one = config.tag.value_equals(Tag::One, Rotation::cur())(meta);
            let tag_is_bit0 = config.tag.value_equals(Tag::Bit0, Rotation::cur())(meta);
            let tag_is_bit1 = config.tag.value_equals(Tag::Bit1, Rotation::cur())(meta);
            let tag_is_square = config.tag.value_equals(Tag::Square, Rotation::cur())(meta);
            // get current base
            let base_hi = meta.query_advice(config.base[0], Rotation::cur());
            let base_lo = meta.query_advice(config.base[1], Rotation::cur());
            // get prev base
            let prev_base_hi = meta.query_advice(config.base[0], Rotation::prev());
            let prev_base_lo = meta.query_advice(config.base[1], Rotation::prev());
            vec![
                (
                    "tag is ONE,SQUARE,BIT => base hi = prev base hi",
                    q_enable.clone()
                        * (tag_is_one.clone()
                            + tag_is_square.clone()
                            + tag_is_bit0.clone()
                            + tag_is_bit1.clone())
                        * (base_hi.clone() - prev_base_hi.clone()),
                ),
                (
                    "tag is ONE,SQUARE,BIT => base lo = prev base lo",
                    q_enable.clone()
                        * (tag_is_one.clone()
                            + tag_is_square.clone()
                            + tag_is_bit0.clone()
                            + tag_is_bit1.clone())
                        * (base_lo.clone() - prev_base_lo.clone()),
                ),
            ]
        });
        // constrain tag
        // if TAG is ZERO, then tag_prev must be ZERO or BIT
        // if TAG is ONE, then tag_prev must be ZERO
        // if TAG is SQUARE, then tag_prev must be BIT
        // if TAG is BIT, then tag_prev must be ONE or SQUARE
        meta.create_gate("EXP_TAG", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let tag_is_zero = config.tag.value_equals(Tag::Zero, Rotation::cur())(meta);
            let tag_prev_is_zero = config.tag.value_equals(Tag::Zero, Rotation::prev())(meta);

            let tag_is_square = config.tag.value_equals(Tag::Square, Rotation::cur())(meta);
            let tag_prev_is_bit0 = config.tag.value_equals(Tag::Bit0, Rotation::prev())(meta);
            let tag_prev_is_bit1 = config.tag.value_equals(Tag::Bit1, Rotation::prev())(meta);

            let tag_is_bit0 = config.tag.value_equals(Tag::Bit0, Rotation::cur())(meta);
            let tag_is_bit1 = config.tag.value_equals(Tag::Bit1, Rotation::cur())(meta);
            let tag_prev_is_one = config.tag.value_equals(Tag::One, Rotation::prev())(meta);
            let tag_prev_is_square = config.tag.value_equals(Tag::Square, Rotation::prev())(meta);
            let tag_is_one = config.tag.value_equals(Tag::One, Rotation::cur())(meta);
            vec![
                (
                    "tag is ZERO => tag_prev is ZERO or BIT",
                    q_enable.clone()
                        * tag_is_zero
                        * (1.expr()
                            - tag_prev_is_zero.clone()
                            - tag_prev_is_bit0.clone()
                            - tag_prev_is_bit1.clone()),
                ),
                (
                    "tag is ONE => tag_prev is ZERO",
                    q_enable.clone() * tag_is_one * (1.expr() - tag_prev_is_zero),
                ),
                (
                    "tag is SQUARE => tag_prev is BIT(BIT0 or BIT1)",
                    q_enable.clone()
                        * tag_is_square
                        * (1.expr() - tag_prev_is_bit0 - tag_prev_is_bit1),
                ),
                (
                    "tag is BIT => tag_prev is ONE or SQUARE",
                    q_enable.clone()
                        * (tag_is_bit0 + tag_is_bit1)
                        * (1.expr() - tag_prev_is_one - tag_prev_is_square),
                ),
            ]
        });

        // constrain count
        // if TAG is ZERO, then COUNT is 0
        // if TAG is ONE, then COUNT is 0
        // if TAG is SQUARE, then COUNT is COUNT_prev+1
        // if TAG is BIT, then COUNT is COUNT_prev
        meta.create_gate("EXP_COUNT", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let count = meta.query_advice(config.count, Rotation::cur());
            let count_prev = meta.query_advice(config.count, Rotation::prev());
            let tag_is_zero = config.tag.value_equals(Tag::Zero, Rotation::cur())(meta);
            let tag_is_square = config.tag.value_equals(Tag::Square, Rotation::cur())(meta);
            let tag_is_bit0 = config.tag.value_equals(Tag::Bit0, Rotation::cur())(meta);
            let tag_is_bit1 = config.tag.value_equals(Tag::Bit1, Rotation::cur())(meta);
            let tag_is_one = config.tag.value_equals(Tag::One, Rotation::cur())(meta);
            vec![
                (
                    "tag is ZERO => count is 0",
                    q_enable.clone() * tag_is_zero * count.clone(),
                ),
                (
                    "tag is ONE => count is 0",
                    q_enable.clone() * tag_is_one * count.clone(),
                ),
                (
                    "tag is SQUARE => count is count_prev+1",
                    q_enable.clone()
                        * tag_is_square
                        * (count.clone() - count_prev.clone() - 1.expr()),
                ),
                (
                    "tag is BIT => count is count_prev",
                    q_enable.clone() * (tag_is_bit0 + tag_is_bit1) * (count - count_prev),
                ),
            ]
        });

        // constrain index, power
        // if TAG is ZERO, then index is 0, power is 1
        // if TAG is ONE, then index is 1, power is BASE
        // if TAG is SQUARE, then index is equal to index_prev_prev*2(if count is 128, then index_cur_hi is 1, index_cur_lo is 0),
        //                      power is equal to power_prev_prev * power_prev_prev(lookup arithmetic)
        // if TAG is BIT0, index is equal to index_prev_prev, power is equal to power_prev_prev  (BIT0)
        // if TAG is BIT1, then index hi/lo is equal to index_hi/lo_prev_prev + index_hi/lo_prev;
        meta.create_gate("EXP_POWER_INDEX", |meta| {
            let q_enable = meta.query_selector(config.q_enable);

            // get current tag
            let tag_is_zero = config.tag.value_equals(Tag::Zero, Rotation::cur())(meta);
            let tag_is_one = config.tag.value_equals(Tag::One, Rotation::cur())(meta);
            let tag_is_square = config.tag.value_equals(Tag::Square, Rotation::cur())(meta);
            let tag_is_bit1 = config.tag.value_equals(Tag::Bit1, Rotation::cur())(meta);
            // get current index
            let index_hi = meta.query_advice(config.index[0], Rotation::cur());
            let index_lo = meta.query_advice(config.index[1], Rotation::cur());

            // get current base
            let base_hi = meta.query_advice(config.base[0], Rotation::cur());
            let base_lo = meta.query_advice(config.base[1], Rotation::cur());

            // get current power
            let power_hi = meta.query_advice(config.power[0], Rotation::cur());
            let power_lo = meta.query_advice(config.power[1], Rotation::cur());

            let tag_is_bit0 = config.tag.value_equals(Tag::Bit0, Rotation::cur())(meta);
            let index_hi_prev_prev = meta.query_advice(config.index[0], Rotation(-2));
            let index_lo_prev_prev = meta.query_advice(config.index[1], Rotation(-2));
            let index_hi_prev = meta.query_advice(config.index[0], Rotation::prev());
            let index_lo_prev = meta.query_advice(config.index[1], Rotation::prev());

            let power_hi_prev_prev = meta.query_advice(config.power[0], Rotation(-2));
            let power_lo_prev_prev = meta.query_advice(config.power[1], Rotation(-2));

            let count_is_128 = config.count_is_128.expr();

            vec![
                (
                    "tag is ZERO => index hi is 0 ",
                    q_enable.clone() * tag_is_zero.clone() * index_hi.clone(),
                ),
                (
                    "tag is ZERO => index lo is 0",
                    q_enable.clone() * tag_is_zero.clone() * index_lo.clone(),
                ),
                (
                    "tag is ZERO => power hi is 0",
                    q_enable.clone() * tag_is_zero.clone() * power_hi.clone(),
                ),
                (
                    "tag is ZERO => power lo is 1",
                    q_enable.clone() * tag_is_zero.clone() * (1.expr() - power_lo.clone()),
                ),
                (
                    "tag is ONE => index hi is 0",
                    q_enable.clone() * tag_is_one.clone() * index_hi.clone(),
                ),
                (
                    "tag is ONE => index lo is 1",
                    q_enable.clone() * tag_is_one.clone() * (1.expr() - index_lo.clone()),
                ),
                (
                    "tag is ONE => power hi is base hi",
                    q_enable.clone() * tag_is_one.clone() * (power_hi.clone() - base_hi),
                ),
                (
                    "tag is ONE => power lo is base lo",
                    q_enable.clone() * tag_is_one * (power_lo.clone() - base_lo),
                ),
                (
                    "tag is bit0 => index hi is equal to index_hi_prev_prev ",
                    q_enable.clone()
                        * tag_is_bit0.clone()
                        * (index_hi.clone() - index_hi_prev_prev.clone()),
                ),
                (
                    "tag is bit0 => index lo is equal to index_lo_prev_prev",
                    q_enable.clone()
                        * tag_is_bit0.clone()
                        * (index_lo.clone() - index_lo_prev_prev.clone()),
                ),
                (
                    "tag is bit0 => power hi is equal to power_hi_prev_prev",
                    q_enable.clone() * tag_is_bit0.clone() * (power_hi - power_hi_prev_prev),
                ),
                (
                    "tag is bit0 => power lo is equal to power_lo_prev_prev",
                    q_enable.clone() * tag_is_bit0.clone() * (power_lo - power_lo_prev_prev),
                ),
                (
                    "tag is SQUARE and count is 128 => index_hi is 1",
                    q_enable.clone()
                        * tag_is_square.clone()
                        * count_is_128.clone()
                        * (1.expr() - index_hi.clone()),
                ),
                (
                    "tag is SQUARE and count is 128 => index_lo is 0",
                    q_enable.clone()
                        * tag_is_square.clone()
                        * count_is_128.clone()
                        * index_lo.clone(),
                ),
                (
                    "tag is SQUARE and count is not 128 => index_hi is  2 * index_hi_prev_prev ",
                    q_enable.clone()
                        * tag_is_square.clone()
                        * (1.expr() - count_is_128.clone())
                        * (index_hi.clone() - index_hi_prev_prev.clone() * 2.expr()),
                ),
                (
                    "tag is SQUARE and count is not 128 => index_lo is  2 * index_lo_prev_prev ",
                    q_enable.clone()
                        * tag_is_square.clone()
                        * (1.expr() - count_is_128.clone())
                        * (index_lo.clone() - index_lo_prev_prev.clone() * 2.expr()),
                ),
                (
                    "tag is bit1 => index hi is index_hi_prev_prev + index_hi_prev",
                    q_enable.clone()
                        * tag_is_bit1.clone()
                        * (index_hi.clone() - index_hi_prev_prev.clone() - index_hi_prev.clone()),
                ),
                (
                    "tag is bit1 => index lo is index_lo_prev_prev + index_lo_prev",
                    q_enable.clone()
                        * tag_is_bit1.clone()
                        * (index_lo.clone() - index_lo_prev_prev.clone() - index_lo_prev.clone()),
                ),
            ]
        });

        // addition and multiplication operation results use lookup constraints
        config.arithmetic_lookup(meta, "EXP_LOOKUP");

        config
    }
}

impl<F: Field> ExpCircuitConfig<F> {
    /// assign data to exp circuit table
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let tag: BinaryNumberChip<F, Tag, LOG_NUM_EXP_TAG> = BinaryNumberChip::construct(self.tag);
        let count_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.count_is_zero.clone());
        let count_is_128 = IsZeroChip::construct(self.count_is_128.clone());

        tag.assign(region, offset, &row.tag)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.base_hi, self.base[0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.base_lo, self.base[1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.index_hi, self.index[0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.index_lo, self.index[1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.power_hi, self.power[0])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.power_lo, self.power[1])?;
        assign_advice_or_fixed_with_u256(region, offset, &row.count, self.count)?;
        // assign_advice_or_fixed(region, offset, &row.is_high, self.is_high)?;

        count_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.count))),
        )?;

        count_is_128.assign(
            region,
            offset,
            Value::known(
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.count)) - F::from(V_128),
            ),
        )?;

        Ok(())
    }

    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // assign the rest rows
        for (offset, row) in witness.exp.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }

        // pad the rest rows
        for offset in witness.exp.len()..num_row_incl_padding {
            self.assign_row(region, offset, &Default::default())?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        self.tag.annotate_columns_in_region(region, "exp_tag");
        region.name_column(|| "exp_base_hi", self.base[0]);
        region.name_column(|| "exp_base_lo", self.base[1]);
        region.name_column(|| "exp_index_hi", self.index[0]);
        region.name_column(|| "exp_index_lo", self.index[1]);
        region.name_column(|| "exp_power_hi", self.power[0]);
        region.name_column(|| "exp_power_lo", self.power[1]);
        region.name_column(|| "exp_count", self.count);
        // region.name_column(|| "exp_is_high", self.is_high);
    }

    /// if TAG is SQUARE, then  power is equal to power_prev_prev * power_prev_prev(lookup arithmetic)
    /// if TAG is BIT1，  power is power_prev * power_prev_prev (lookup arithmetic)
    ///     lookup src: exp circuit
    ///     lookup target: arithmetic circuit table
    pub fn arithmetic_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        meta.lookup_any(format!("{}_SQUARE_POW", name).as_str(), |meta| {
            // get current tag
            let tag_is_square = self.tag.value_equals(Tag::Square, Rotation::cur())(meta);
            let q_enable = meta.query_selector(self.q_enable);

            // if TAG is SQUARE, then power is equal to power_prev_prev * power_prev_prev(lookup arithmetic)
            let power_prev_prev_hi = meta.query_advice(self.power[0], Rotation(-2));
            let power_prev_prev_lo = meta.query_advice(self.power[1], Rotation(-2));
            let square_power_entry = LookupEntry::ArithmeticShort {
                tag: (arithmetic::Tag::Mul as u8).expr(),
                values: [
                    power_prev_prev_hi.clone(),
                    power_prev_prev_lo.clone(),
                    power_prev_prev_hi.clone(),
                    power_prev_prev_lo.clone(),
                    meta.query_advice(self.power[0], Rotation::cur()), // power_cur_hi
                    meta.query_advice(self.power[1], Rotation::cur()), // power_cur_lo
                ],
            };

            let square_power_lookup_vec = self
                .arithmetic_table
                .get_lookup_vector(meta, square_power_entry.clone());

            square_power_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    (
                        // if count is 128, then index_cur_hi is 1, index_cur_lo is 0 (no lookup required)
                        q_enable.clone() * tag_is_square.clone() * left,
                        right,
                    )
                })
                .collect()
        });
        meta.lookup_any(format!("{}_BIT1_POW", name).as_str(), |meta| {
            // get current tag
            let tag_is_bit1 = self.tag.value_equals(Tag::Bit1, Rotation::cur())(meta);

            // if TAG is BIT1， then power is power_prev * power_prev_prev (lookup arithmetic)
            let bit1_power_entry = LookupEntry::ArithmeticShort {
                tag: (arithmetic::Tag::Mul as u8).expr(),
                values: [
                    meta.query_advice(self.power[0], Rotation(-2)), // power_hi_prev_prev
                    meta.query_advice(self.power[1], Rotation(-2)), // power_lo_prev_prev
                    meta.query_advice(self.power[0], Rotation::prev()), // power_hi_prev
                    meta.query_advice(self.power[1], Rotation::prev()), // power_lo_prev
                    meta.query_advice(self.power[0], Rotation::cur()), // power_cur_hi
                    meta.query_advice(self.power[1], Rotation::cur()), // power_cur_lo
                ],
            };

            let bit1_power_lookup_vec = self
                .arithmetic_table
                .get_lookup_vector(meta, bit1_power_entry.clone());

            bit1_power_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    (
                        // if count is 128, then index_cur_hi is 1, index_cur_lo is 0 (no lookup required)
                        q_enable.clone() * tag_is_bit1.clone() * left,
                        right,
                    )
                })
                .collect()
        });
    }
}

#[derive(Clone, Default, Debug)]
pub struct ExpCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for ExpCircuit<F, MAX_NUM_ROW> {
    type Config = ExpCircuitConfig<F>;
    type Cells = ();
    fn new_from_witness(witness: &Witness) -> Self {
        ExpCircuit {
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
            || "exp circuit",
            |mut region| {
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assign circuit table value
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;

                // sub circuit need to enable selector
                for offset in num_padding_begin..self.witness.exp.len() - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }
    fn unusable_rows() -> (usize, usize) {
        (2, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.exp.len()
    }
}

/// test exp circuit constrain and exp value lookup
#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic_circuit::{
        ArithmeticCircuit, ArithmeticCircuitConfig, ArithmeticCircuitConfigArgs,
    };
    use crate::util::log2_ceil;
    use crate::witness::{exp, Witness};
    use eth_types::U256;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Circuit;
    use serde::Serialize;

    // used to test whether the function of exp circuit Lookup is correct
    // Exp lookup, src: ExpTestCircuit  target: exp circuit
    #[derive(Clone, Debug, Default, Serialize)]
    pub struct ExpTestRow {
        pub base: [U256; EXP_NUM_OPERAND],
        pub index: [U256; EXP_NUM_OPERAND],
        pub pow: [U256; EXP_NUM_OPERAND],
    }

    #[derive(Clone)]
    pub struct ExpTestCircuitConfig<F: Field> {
        q_enable: Selector,
        pub exp_circuit: ExpCircuitConfig<F>,
        pub arithmetic_circuit: ArithmeticCircuitConfig<F>,
        /// base hi , base lo
        pub base: [Column<Advice>; EXP_NUM_OPERAND],
        /// index hi, index lo
        pub index: [Column<Advice>; EXP_NUM_OPERAND],
        /// power hi, power lo
        pub pow: [Column<Advice>; EXP_NUM_OPERAND],
        /// challenges
        pub challenges: Challenges,
    }

    impl<F: Field> SubCircuitConfig<F> for ExpTestCircuitConfig<F> {
        type ConfigArgs = ();

        /// Constructor， used to construct config object
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            let q_enable = meta.complex_selector();
            let q_enable_arithmetic = meta.complex_selector();
            let arithmetic_table = ArithmeticTable::construct(meta, q_enable_arithmetic);
            let exp_table = ExpTable::construct(meta);
            let challenges = Challenges::construct(meta);
            let exp_circuit = ExpCircuitConfig::new(
                meta,
                ExpCircuitConfigArgs {
                    arithmetic_table,
                    exp_table,
                },
            );

            let arithmetic_circuit = ArithmeticCircuitConfig::new(
                meta,
                ArithmeticCircuitConfigArgs {
                    q_enable: q_enable_arithmetic,
                    arithmetic_table,
                },
            );

            let base: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
            let index: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
            let pow: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
            ExpTestCircuitConfig {
                q_enable,
                exp_circuit,
                arithmetic_circuit,
                base,
                index,
                pow,
                challenges,
            }
        }
    }
    impl<F: Field> ExpTestCircuitConfig<F> {
        /// assign ExpTestCircuit rows
        pub fn assign_with_region(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &ExpTestRow,
        ) -> Result<(), Error> {
            assign_advice_or_fixed_with_u256(region, offset, &row.base[0], self.base[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.base[1], self.base[1])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.index[0], self.index[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.index[1], self.index[1])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.pow[0], self.pow[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.pow[1], self.pow[1])?;
            Ok(())
        }
    }

    /// ExpTestCircuitConfig is a Circuit used for testing
    #[derive(Clone, Default, Debug)]
    pub struct ExpTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub exp_circuit: ExpCircuit<F, MAX_NUM_ROW>,
        pub arithmetic_circuit: ArithmeticCircuit<F, MAX_NUM_ROW>,
        pub rows: Vec<ExpTestRow>,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for ExpTestCircuit<F, MAX_NUM_ROW> {
        type Config = ExpTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // construct config object
            let config = Self::Config::new(meta, ());

            // Lookup logic code
            // used to verify whether base, index, pow can be correctly looked up
            meta.lookup_any("EXP_TEST_LOOKUP", |meta| {
                // get the value of the specified Column in ExpTestCircuit
                let exp_entry_base_hi = meta.query_advice(config.base[0], Rotation::cur());
                let exp_entry_base_lo = meta.query_advice(config.base[1], Rotation::cur());

                let exp_entry_index_hi = meta.query_advice(config.index[0], Rotation::cur());
                let exp_entry_index_lo = meta.query_advice(config.index[1], Rotation::cur());

                let exp_entry_pow_hi = meta.query_advice(config.pow[0], Rotation::cur());
                let exp_entry_pow_lo = meta.query_advice(config.pow[1], Rotation::cur());

                // get the value of the specified Column in ExpCircuit
                let exp_circuit_base_hi =
                    meta.query_advice(config.exp_circuit.base[0], Rotation::cur());
                let exp_circuit_base_lo =
                    meta.query_advice(config.exp_circuit.base[1], Rotation::cur());

                let exp_circuit_index_hi =
                    meta.query_advice(config.exp_circuit.index[0], Rotation::cur());
                let exp_circuit_index_lo =
                    meta.query_advice(config.exp_circuit.index[1], Rotation::cur());

                let exp_circuit_pow_hi =
                    meta.query_advice(config.exp_circuit.power[0], Rotation::cur());
                let exp_circuit_pow_lo =
                    meta.query_advice(config.exp_circuit.power[1], Rotation::cur());

                let q_enable = meta.query_selector(config.q_enable);
                vec![
                    (q_enable.clone() * exp_entry_base_hi, exp_circuit_base_hi),
                    (q_enable.clone() * exp_entry_base_lo, exp_circuit_base_lo),
                    (q_enable.clone() * exp_entry_index_hi, exp_circuit_index_hi),
                    (q_enable.clone() * exp_entry_index_lo, exp_circuit_index_lo),
                    (q_enable.clone() * exp_entry_pow_hi, exp_circuit_pow_hi),
                    (q_enable.clone() * exp_entry_pow_lo, exp_circuit_pow_lo),
                ]
            });

            config
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.exp_circuit
                .synthesize_sub(&config.exp_circuit, &mut layouter, &challenges)?;

            self.arithmetic_circuit.synthesize_sub(
                &config.arithmetic_circuit,
                &mut layouter,
                &challenges,
            )?;

            layouter.assign_region(
                || "exp circuit test",
                |mut region| {
                    for (offset, row) in self.rows.iter().enumerate() {
                        config.q_enable.enable(&mut region, offset)?;
                        config.assign_with_region(&mut region, offset, row)?;
                    }
                    Ok(())
                },
            )
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> ExpTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness, rows: Vec<ExpTestRow>) -> Self {
            Self {
                exp_circuit: ExpCircuit::new_from_witness(&witness),
                arithmetic_circuit: ArithmeticCircuit::new_from_witness(&witness),
                rows,
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.exp_circuit.instance());
            vec.extend(self.arithmetic_circuit.instance());
            vec
        }
    }

    fn test_simple_exp_circuit<F: Field, const TEST_SIZE: usize>(
        witness: Witness,
        rows: Vec<ExpTestRow>,
    ) -> MockProver<Fr> {
        let k = log2_ceil(TEST_SIZE);
        let circuit = ExpTestCircuit::<Fr, TEST_SIZE>::new(witness, rows);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover
    }

    fn test_exp_circuit<const TEST_SIZE: usize>(
        base: U256,
        index: U256,
        lookup_exp_row: ExpTestRow,
    ) {
        // get exp rows
        let (calc_pow, exp_rows, arithmetic_mul_rows) = exp::Row::from_operands(base, index);

        let expect_pow = (lookup_exp_row.pow[0] << 128) + lookup_exp_row.pow[1];
        assert_eq!(calc_pow, expect_pow);

        println!("actual_calc_pow:{}, expect_pow:{}", calc_pow, expect_pow);

        // fill rows into witnesses
        let mut witness = Witness::default();
        (0..ExpCircuit::<Fr, TEST_SIZE>::unusable_rows().0)
            .for_each(|_| witness.exp.insert(0, Default::default()));
        (0..ArithmeticCircuit::<Fr, TEST_SIZE>::unusable_rows().0)
            .for_each(|_| witness.arithmetic.insert(0, Default::default()));

        witness.exp.extend(exp_rows);
        witness.arithmetic.extend(arithmetic_mul_rows);

        //witness.print_csv();
        // let mut buf = std::io::BufWriter::new(File::create("exp.html").unwrap());
        // witness.write_html(&mut buf);

        // execution circuit
        let prover = test_simple_exp_circuit::<Fr, TEST_SIZE>(witness, vec![lookup_exp_row]);
        prover.assert_satisfied();
    }

    #[test]
    fn test_exp1() {
        // calc 2^10
        const TEST_SIZE: usize = 200;
        let base = U256::from(3);
        let index = U256::from(10);

        let (expect_pow, _) = base.overflowing_pow(index);

        let exp_test_row = ExpTestRow {
            base: [base >> 128, U256::from(base.low_u128())],
            index: [index >> 128, U256::from(index.low_u128())],
            pow: [expect_pow >> 128, U256::from(expect_pow.low_u128())],
        };
        test_exp_circuit::<TEST_SIZE>(base, index, exp_test_row)
    }

    #[test]
    fn test_exp2() {
        // calc 3^10
        const TEST_SIZE: usize = 200;
        let base = U256::from(2);
        let index = U256::from(257);

        let (expect_pow, _) = base.overflowing_pow(index);

        let exp_test_row = ExpTestRow {
            base: [base >> 128, U256::from(base.low_u128())],
            index: [index >> 128, U256::from(index.low_u128())],
            pow: [expect_pow >> 128, U256::from(expect_pow.low_u128())],
        };
        test_exp_circuit::<TEST_SIZE>(base, index, exp_test_row)
    }

    #[test]
    fn test_exp3() {
        // calc 3^128
        const TEST_SIZE: usize = 5000;
        let base = U256::from(3);

        let (index, _) = U256::from(2).overflowing_pow(U256::from(128));
        let (expect_pow, _) = base.overflowing_pow(index);

        let exp_test_row = ExpTestRow {
            base: [base >> 128, U256::from(base.low_u128())],
            index: [index >> 128, U256::from(index.low_u128())],
            pow: [expect_pow >> 128, U256::from(expect_pow.low_u128())],
        };
        test_exp_circuit::<TEST_SIZE>(base, index, exp_test_row)
    }

    #[test]
    fn test_exp4() {
        // calc 3^210
        const TEST_SIZE: usize = 5000;
        let base = U256::from(3);

        let (index, _) = U256::from(2).overflowing_pow(U256::from(210));
        let (expect_pow, _) = base.overflowing_pow(index);

        let exp_test_row = ExpTestRow {
            base: [base >> 128, U256::from(base.low_u128())],
            index: [index >> 128, U256::from(index.low_u128())],
            pow: [expect_pow >> 128, U256::from(expect_pow.low_u128())],
        };
        test_exp_circuit::<TEST_SIZE>(base, index, exp_test_row)
    }

    #[test]
    fn test_exp5() {
        // calc 3^257
        const TEST_SIZE: usize = 5000;
        let base = U256::from(3);

        let (index, _) = U256::from(2).overflowing_pow(U256::from(257));
        let (expect_pow, _) = base.overflowing_pow(index);

        let exp_test_row = ExpTestRow {
            base: [base >> 128, U256::from(base.low_u128())],
            index: [index >> 128, U256::from(index.low_u128())],
            pow: [expect_pow >> 128, U256::from(expect_pow.low_u128())],
        };
        test_exp_circuit::<TEST_SIZE>(base, index, exp_test_row)
    }
}
