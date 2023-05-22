//! The Dynamic selector chip implements selector that reduces the number of columns.
//! Reduce N columns to about 2sqrt(N) columns.
//!
//! It works as follows:
//!
//! For a upper bound value of selectors `COUNT`, we need `N + M` columns s.t. `N * M >= COUNT`. Optimal choice of `N` is `sqrt(COUNT)`.
//! `N` columns denoted as `target_high`, `M` columns as `target_low`. One column among `target_high` is 1 and others are 0. Ditto with `target_low`.
//! For a target selector index in [0, COUNT-1], return the expression of `target_high[i]*target_low[j]` where `i=target/M`, `j=target%M`.

use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::circuit::{Chip, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Dynamic selector that generates expressions of degree 2 to select from N
/// possible targets using about 2 sqrt(N) cells..
#[derive(Clone, Debug)]
pub struct DynamicSelectorConfig<F> {
    #[allow(dead_code)]
    /// N value: how many possible targets this selector supports.
    count: usize,
    /// target = i * low_len + j
    /// selector = high[i] * low[j]
    target_high: Vec<Column<Advice>>,
    target_low: Vec<Column<Advice>>,
    _marker: PhantomData<F>,
}

impl<F: Field> DynamicSelectorConfig<F> {
    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region(&self, region: &mut Region<F>, prefix: &str) {
        self.target_high
            .iter()
            .enumerate()
            .for_each(|(index, col)| {
                region.name_column(|| format!("{}_high_{}", prefix, index), *col)
            });
        self.target_low.iter().enumerate().for_each(|(index, col)| {
            region.name_column(|| format!("{}_low_{}", prefix, index), *col)
        });
    }

    /// Get the selector value of target
    pub fn selector(&self, meta: &mut VirtualCells<F>, target: usize) -> Expression<F> {
        let high = target / self.target_low.len();
        let low = target % self.target_low.len();
        let target_high = meta.query_advice(self.target_high[high], Rotation::cur());
        let target_low = meta.query_advice(self.target_low[low], Rotation::cur());
        target_high * target_low
    }
}

/// Wrapper arround [`DynamicSelectorChip`] for which [`Chip`] is implemented.
pub struct DynamicSelectorChip<F> {
    config: DynamicSelectorConfig<F>,
}

impl<F: Field> DynamicSelectorChip<F> {
    /// Sets up the configuration of the chip, and own the necessary columns
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        count: usize,
        target_high: Vec<Column<Advice>>,
        target_low: Vec<Column<Advice>>,
    ) -> DynamicSelectorConfig<F> {
        assert!(target_high.len() * target_low.len() >= count);
        meta.create_gate("dynamic_selector gate", |meta| {
            let q_enable = q_enable(meta);
            let mut constraints: Vec<(&str, Expression<F>)> = target_high
                .iter()
                .chain(target_low.iter())
                .map(|col| {
                    let x = meta.query_advice(col.clone(), Rotation::cur());
                    (
                        "selector bool",
                        q_enable.clone() * x.clone() * (1u8.expr() - x),
                    )
                })
                .collect();
            let sum_high = target_high
                .iter()
                .map(|col| meta.query_advice(col.clone(), Rotation::cur()))
                .reduce(|acc, expr| acc + expr)
                .unwrap();
            constraints.push(("sum_high = 1", q_enable.clone() * (sum_high - 1u8.expr())));
            let sum_low = target_low
                .iter()
                .map(|col| meta.query_advice(col.clone(), Rotation::cur()))
                .reduce(|acc, expr| acc + expr)
                .unwrap();
            constraints.push(("sum_low = 1", q_enable.clone() * (sum_low - 1u8.expr())));

            constraints
        });

        DynamicSelectorConfig {
            count,
            target_high,
            target_low,
            _marker: Default::default(),
        }
    }

    /// Assign the DynamicSelectorChip
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        target: usize,
    ) -> Result<(), Error> {
        let high = target / self.config.target_low.len();
        let low = target % self.config.target_low.len();

        for (index, col) in self.config.target_high.iter().enumerate() {
            region.assign_advice(
                || format!("target_high {}", index),
                col.clone(),
                offset,
                || Value::known(if index == high { F::one() } else { F::zero() }),
            )?;
        }
        for (index, col) in self.config.target_low.iter().enumerate() {
            region.assign_advice(
                || format!("target_low {}", index),
                col.clone(),
                offset,
                || Value::known(if index == low { F::one() } else { F::zero() }),
            )?;
        }
        Ok(())
    }

    /// Given an `DynamicSelectorChip`, construct the chip.
    pub fn construct(config: DynamicSelectorConfig<F>) -> Self {
        Self { config }
    }
}

impl<F: Field> Chip<F> for DynamicSelectorChip<F> {
    type Config = DynamicSelectorConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod test {
    use super::{DynamicSelectorChip, DynamicSelectorConfig};
    use eth_types::Field;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    };
    use halo2_proofs::poly::Rotation;
    use std::marker::PhantomData;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<F> {
        q_enable: Selector,
        /// covert target values to 0/1 table by brutal force, for test check
        zero_one_values: Vec<Column<Fixed>>,
        dynamic_selector: DynamicSelectorConfig<F>,
    }

    #[derive(Default)]
    struct TestCircuit<F: Field, const COUNT: usize> {
        values: Vec<u64>,
        _marker: PhantomData<F>,
    }

    impl<F: Field, const COUNT: usize> Circuit<F> for TestCircuit<F, COUNT> {
        type Config = TestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable = meta.complex_selector();
            let lo_cnt = (COUNT as f64).sqrt().floor();
            let hi_cnt = ((COUNT as f64) / lo_cnt).floor();
            let target_low = (0..lo_cnt as usize).map(|_| meta.advice_column()).collect();
            let target_high: Vec<Column<Advice>> =
                (0..hi_cnt as usize).map(|_| meta.advice_column()).collect();
            let dynamic_selector = DynamicSelectorChip::configure(
                meta,
                |meta| meta.query_selector(q_enable),
                COUNT,
                target_high,
                target_low,
            );
            let zero_one_values: Vec<Column<Fixed>> =
                (0..COUNT).map(|_| meta.fixed_column()).collect();

            // gate for test
            meta.create_gate("test gate", |meta| {
                let q_enable = meta.query_selector(q_enable);
                let mut constraints: Vec<(&str, Expression<F>)> = vec![];
                for target in 0..COUNT {
                    let expr = dynamic_selector.selector(meta, target);
                    let expr_should_be = meta.query_fixed(zero_one_values[target], Rotation::cur());
                    constraints.push((
                        "target constraint",
                        q_enable.clone() * (expr - expr_should_be),
                    ))
                }
                constraints
            });

            Self::Config {
                q_enable,
                dynamic_selector,
                zero_one_values,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let dynamic_selector = DynamicSelectorChip::construct(config.dynamic_selector);
            layouter.assign_region(
                || "witness",
                |mut region| {
                    for (offset, value) in self.values.iter().enumerate() {
                        config.q_enable.enable(&mut region, offset)?;
                        dynamic_selector.assign(&mut region, offset, *value as usize)?;
                        for target in 0..COUNT {
                            region.assign_fixed(
                                || "zero_one_values",
                                config.zero_one_values[target],
                                offset,
                                || {
                                    Value::known(if target == *value as usize {
                                        F::one()
                                    } else {
                                        F::zero()
                                    })
                                },
                            )?;
                        }
                    }
                    Ok(())
                },
            )
        }
    }

    macro_rules! gen_try_test_circuit {
        ($count:expr) => {
            fn try_test_circuit(values: Vec<u64>) {
                let circuit = TestCircuit::<Fp, $count> {
                    values: values,
                    _marker: PhantomData,
                };
                let k = 9;
                let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
                prover.assert_satisfied_par()
            }
        };
    }

    #[test]
    fn correct_expr_of_selector() {
        const COUNT: u64 = 256;
        gen_try_test_circuit!({ COUNT as usize });
        try_test_circuit((0..COUNT).collect());
    }
}
