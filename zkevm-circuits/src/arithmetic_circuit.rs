// Toy example

mod operation;

use crate::arithmetic_circuit::operation::OperationGadget;
use crate::util::{self, SubCircuit, SubCircuitConfig};
use crate::witness::block::{SelectorColumn, StackCircuitWitness};
use crate::witness::{arithmetic, Block};
use arithmetic::{Row, Tag};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Clone)]
pub struct ArithmeticCircuitConfig<F> {
    // TODO use table to let core lookup
    q_enable: Selector,
    // arithmetic table for lookup starts
    tag: BinaryNumberConfig<Tag, 3>, //todo not use 3
    cnt: Column<Advice>,
    operand0_hi: Column<Advice>,
    operand0_lo: Column<Advice>,
    operand1_hi: Column<Advice>,
    operand1_lo: Column<Advice>,
    operand2_hi: Column<Advice>,
    operand2_lo: Column<Advice>,
    operand3_hi: Column<Advice>,
    operand3_lo: Column<Advice>,
    // arithmetic table for lookup ends
    u16_0: Column<Advice>,
    u16_1: Column<Advice>,
    u16_2: Column<Advice>,
    u16_3: Column<Advice>,
    u16_4: Column<Advice>,
    u16_5: Column<Advice>,
    u16_6: Column<Advice>,
    u16_7: Column<Advice>,
    cnt_is_zero: IsZeroWithRotationConfig<F>,
}

pub struct NilCircuitConfigArgs {} // todo change this

impl<F: Field> SubCircuitConfig<F> for ArithmeticCircuitConfig<F> {
    type ConfigArgs = NilCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        // init columns
        let q_enable = meta.complex_selector();
        let cnt = meta.advice_column();
        let operand0_hi = meta.advice_column();
        let operand0_lo = meta.advice_column();
        let operand1_hi = meta.advice_column();
        let operand1_lo = meta.advice_column();
        let operand2_hi = meta.advice_column();
        let operand2_lo = meta.advice_column();
        let operand3_hi = meta.advice_column();
        let operand3_lo = meta.advice_column();
        let u16_0 = meta.advice_column();
        let u16_1 = meta.advice_column();
        let u16_2 = meta.advice_column();
        let u16_3 = meta.advice_column();
        let u16_4 = meta.advice_column();
        let u16_5 = meta.advice_column();
        let u16_6 = meta.advice_column();
        let u16_7 = meta.advice_column();
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let config = Self {
            q_enable,
            tag,
            cnt,
            operand0_hi,
            operand0_lo,
            operand1_hi,
            operand1_lo,
            operand2_hi,
            operand2_lo,
            operand3_hi,
            operand3_lo,
            u16_0,
            u16_1,
            u16_2,
            u16_3,
            u16_4,
            u16_5,
            u16_6,
            u16_7,
            cnt_is_zero,
        };
        // constraints
        meta.create_gate("Arithmetic Circuit Common", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_next = meta.query_advice(config.cnt.clone(), Rotation::next());
            let cnt_cur = meta.query_advice(config.cnt.clone(), Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            vec![q_enable * (1.expr() - cnt_is_zero) * (cnt_cur - cnt_next - 1.expr())]
        });
        // todo use a for loop for all gadgets
        meta.create_gate(operation::add::AddGadget::<F>::NAME, |meta| {
            // add selector and tag condition
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let condition = config
                .tag
                .value_equals(operation::add::AddGadget::<F>::TAG, Rotation::cur())(
                meta
            ) * cnt_is_zero;
            let cnt_above = meta.query_advice(
                config.cnt,
                Rotation(1 - operation::add::AddGadget::<F>::NUM_ROW as i32),
            );
            let cnt_above_above = meta.query_advice(
                config.cnt,
                Rotation(0 - operation::add::AddGadget::<F>::NUM_ROW as i32),
            );
            let constraints = vec![
                (
                    "rows of this operation",
                    q_enable.clone()
                        * condition.clone()
                        * (cnt_above - (operation::add::AddGadget::<F>::NUM_ROW - 1).expr()),
                ),
                (
                    "prev operation cnt = 0",
                    q_enable.clone() * condition.clone() * cnt_above_above,
                ),
            ];

            constraints
                .into_iter()
                .chain(operation::add::AddGadget::<F>::constraints(&config, meta).into_iter())
                .map(move |(name, constraint)| {
                    (name, q_enable.clone() * condition.clone() * constraint)
                })
        });

        config
    }
}

#[derive(Clone, Default, Debug)]
pub struct ArithmeticCircuit<F: Field> {
    witness: Vec<Row>,
    _marker: PhantomData<F>,
}

/// A standalone circuit for testing
impl<F: Field> Circuit<F> for ArithmeticCircuit<F> {
    type Config = ArithmeticCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::new(meta, NilCircuitConfigArgs {})
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let tag = BinaryNumberChip::construct(config.tag);
        let cnt_is_zero = IsZeroWithRotationChip::construct(config.cnt_is_zero.clone());

        layouter.assign_region(
            || "arithmetic",
            |mut region| {
                // annotate columns todo
                region.name_column(|| "cnt", config.cnt);
                for (offset, row) in self.witness.iter().enumerate() {
                    region.assign_advice(
                        || "cnt",
                        config.cnt,
                        offset,
                        || Value::known(F::from_u128(row.cnt.unwrap().as_u128())),
                    )?;
                    region.assign_advice(
                        || "operand0_hi",
                        config.operand0_hi,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand0_hi.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand0_lo",
                        config.operand0_lo,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand0_lo.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand1_hi",
                        config.operand1_hi,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand1_hi.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand1_lo",
                        config.operand1_lo,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand1_lo.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand2_hi",
                        config.operand2_hi,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand2_hi.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand2_lo",
                        config.operand2_lo,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand2_lo.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand3_hi",
                        config.operand3_hi,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand3_hi.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "operand3_lo",
                        config.operand3_lo,
                        offset,
                        || {
                            Value::known(F::from_u128(
                                row.operand3_lo.unwrap_or_default().as_u128(),
                            ))
                        },
                    )?;
                    region.assign_advice(
                        || "u16_0",
                        config.u16_0,
                        offset,
                        || Value::known(F::from_u128(row.u16_0.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_1",
                        config.u16_1,
                        offset,
                        || Value::known(F::from_u128(row.u16_1.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_2",
                        config.u16_2,
                        offset,
                        || Value::known(F::from_u128(row.u16_2.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_3",
                        config.u16_3,
                        offset,
                        || Value::known(F::from_u128(row.u16_3.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_4",
                        config.u16_4,
                        offset,
                        || Value::known(F::from_u128(row.u16_4.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_5",
                        config.u16_5,
                        offset,
                        || Value::known(F::from_u128(row.u16_5.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_6",
                        config.u16_6,
                        offset,
                        || Value::known(F::from_u128(row.u16_6.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "u16_7",
                        config.u16_7,
                        offset,
                        || Value::known(F::from_u128(row.u16_7.unwrap_or_default().as_u128())),
                    )?;

                    // do not enable first and last padding row
                    // todo what should be it
                    if offset > 1 && offset < (&self.witness).len() - 1 {
                        config.q_enable.enable(&mut region, offset)?;
                    }
                    tag.assign(&mut region, offset, &row.tag.unwrap_or_default())?;
                    cnt_is_zero.assign(
                        &mut region,
                        offset,
                        Value::known(F::from_u128(row.cnt.unwrap().as_u128())),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> ArithmeticCircuit<F> {
    pub fn new(witness: Vec<Row>) -> Self {
        Self {
            witness,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{IsZeroInstruction, IsZeroWithRotationChip, IsZeroWithRotationConfig};
    use crate::arithmetic_circuit::ArithmeticCircuit;
    use crate::witness::arithmetic::{Row, Tag};
    use eth_types::Field;
    use gadgets::util;
    use gadgets::util::Expr;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    };
    use std::marker::PhantomData;

    fn test_add_two_number(row0: Row, row1: Row) {
        let k = 8;
        let padding = Row::default();
        let rows = vec![padding.clone(), padding.clone(), row0, row1, padding];
        let circuit = ArithmeticCircuit::<Fp>::new(rows);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied_par();
    }

    #[test]
    fn add_0_0() {
        let row0 = Row {
            cnt: Some(1.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        let row1 = Row {
            tag: Some(Tag::Add),
            cnt: Some(0.into()),
            operand0_hi: Some(0.into()),
            operand0_lo: Some(0.into()),
            operand1_hi: Some(0.into()),
            operand1_lo: Some(0.into()),
            operand2_hi: Some(0.into()),
            operand2_lo: Some(0.into()),
            operand3_hi: Some(0.into()),
            operand3_lo: Some(0.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        test_add_two_number(row0, row1);
    }

    #[test]
    fn add_u128max_1() {
        let row0 = Row {
            cnt: Some(1.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        let row1 = Row {
            tag: Some(Tag::Add),
            cnt: Some(0.into()),
            operand0_hi: Some(u128::MAX.into()),
            operand0_lo: Some(u128::MAX.into()),
            operand1_hi: Some(0.into()),
            operand1_lo: Some(1.into()),
            operand2_hi: Some(0.into()),
            operand2_lo: Some(0.into()),
            operand3_hi: Some(1.into()),
            operand3_lo: Some(1.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        test_add_two_number(row0, row1);
    }
}
