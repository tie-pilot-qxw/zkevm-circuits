// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! IsZeroWithRotation gadget works as follows:
//!
//! Given a `value` column to be checked if it is zero:
//!  - witnesses `inv0(value)`, where `inv0(x)` is 0 when `x` = 0, and
//!  `1/x` otherwise

use eth_types::Field;
use halo2_proofs::{
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::is_zero::IsZeroInstruction;
use crate::util::Expr;

/// Config struct representing the required fields for an `IsZero` config to
/// exist.
#[derive(Clone, Copy, Debug)]
pub struct IsZeroWithRotationConfig<F> {
    /// The value. This chip doesn't need to assign it
    pub value: Column<Advice>,
    /// Modular inverse of the value. Need to assign it
    pub value_inv: Column<Advice>,
    /// The result, which is 0 if the value is zero, and 1 otherwise
    pub is_not_zero: Option<Column<Advice>>,

    _marker: PhantomData<F>,
}

impl<F: Field> IsZeroWithRotationConfig<F> {
    /// Returns the is_zero expression at rotation
    pub fn expr_at(&self, meta: &mut VirtualCells<F>, at: Rotation) -> Expression<F> {
        if let Some(is_not_zero) = self.is_not_zero {
            1.expr() - meta.query_advice(is_not_zero, at)
        } else {
            let value = meta.query_advice(self.value, at);
            let value_inv = meta.query_advice(self.value_inv, at);
            1.expr() - value * value_inv
        }
    }

    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region(&self, region: &mut Region<F>, prefix: &str) {
        [(
            self.value_inv,
            "GADGETS_IS_ZERO_WITH_ROTATION_inverse_witness",
        )]
        .iter()
        .for_each(|(col, ann)| region.name_column(|| format!("{}_{}", prefix, ann), *col));
    }
}

/// Wrapper around [`IsZeroWithRotationConfig`] for which [`Chip`] is implemented.
pub struct IsZeroWithRotationChip<F> {
    config: IsZeroWithRotationConfig<F>,
}

#[rustfmt::skip]
impl<F: Field> IsZeroWithRotationChip<F> {
    /// Sets up the configuration of the chip by creating one required column `value_inv` and add constraints
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: Column<Advice>,
        is_not_zero: Option<Column<Advice>>,
    ) -> IsZeroWithRotationConfig<F> {
        let value_inv = meta.advice_column();

        meta.create_gate("is_zero_with_rotation gate", |meta| {
            let q_enable = q_enable(meta);

            let value= meta.query_advice(value, Rotation::cur());
            let value_inv = meta.query_advice(value_inv, Rotation::cur());
            let is_not_zero_expression = value.clone() * value_inv.clone();

            // We wish to satisfy the below constrain for the following cases:
            // 1. value == 0
            // 2. if value != 0, require is_not_zero == 1 => value * value.invert() == 1
            // 3. is_not_zero == value * value.invert()
            if let Some(v) = is_not_zero {
                let is_not_zero = meta.query_advice(v, Rotation::cur());
                vec![(q_enable.clone() * value.clone() *  (1.expr() - is_not_zero.clone())),
                    (q_enable.clone() * (is_not_zero_expression.clone() - is_not_zero.clone()))]
            } else {
                vec![(q_enable.clone() * value.clone() *  (1.expr() - is_not_zero_expression.clone()))]
            }
        });

        IsZeroWithRotationConfig::<F> {
            value,
            value_inv,
            is_not_zero,
            _marker: PhantomData,
        }
    }

    /// Given an `IsZeroConfig`, construct the chip.
    pub fn construct(config: IsZeroWithRotationConfig<F>) -> Self {
        IsZeroWithRotationChip { config }
    }
}

impl<F: Field> IsZeroInstruction<F> for IsZeroWithRotationChip<F> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let config = self.config();
        let value_invert = value.map(|v| v.invert().unwrap_or(F::ZERO));
        region.assign_advice(
            || "witness inverse of value",
            config.value_inv,
            offset,
            || value_invert,
        )?;
        if let Some(v) = config.is_not_zero {
            let is_not_zero = value.map(|v| if v.is_zero_vartime() { F::ZERO } else { F::ONE });
            region.assign_advice(|| "witness is_zero", v, offset, || is_not_zero)?;
        }
        Ok(())
    }
}

impl<F: Field> Chip<F> for IsZeroWithRotationChip<F> {
    type Config = IsZeroWithRotationConfig<F>;
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
    use super::{IsZeroInstruction, IsZeroWithRotationChip, IsZeroWithRotationConfig};
    use eth_types::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    };
    use std::marker::PhantomData;

    macro_rules! try_test_circuit {
        ($values:expr, $checks:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied()
        }};
    }

    macro_rules! try_test_circuit_error {
        ($values:expr, $checks:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn col_is_zero() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig<F> {
            q_enable: Selector,
            value: Column<Advice>,
            check: Column<Advice>,
            is_zero: IsZeroWithRotationConfig<F>,
        }

        #[derive(Default)]
        struct TestCircuit<F: Field> {
            values: Option<Vec<u64>>,
            checks: Option<Vec<bool>>,
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for TestCircuit<F> {
            type Config = TestCircuitConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let value = meta.advice_column();
                let check = meta.advice_column();

                let is_zero = IsZeroWithRotationChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    value,
                    None,
                );

                let config = Self::Config {
                    q_enable,
                    value,
                    check,
                    is_zero,
                };

                meta.create_gate("check is_zero", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies is_zero is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.is_zero.expr_at(meta, Rotation::cur()) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let chip = IsZeroWithRotationChip::construct(config.is_zero.clone());

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| values.iter().map(|value| F::from(*value)).collect())
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        for (idx, (value, check)) in values.iter().zip(checks).enumerate() {
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx,
                                || Value::known(F::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value",
                                config.value,
                                idx,
                                || Value::known(*value),
                            )?;

                            config.q_enable.enable(&mut region, idx)?;
                            chip.assign(&mut region, idx, Value::known(*value))?;
                        }

                        Ok(())
                    },
                )
            }
        }

        // ok
        try_test_circuit!(
            vec![0, 1, 2, 3, 4, 5],
            vec![true, false, false, false, false, false]
        );
        // error
        try_test_circuit_error!(vec![1, 2, 3, 4, 5], vec![true, true, true, true, true]);
    }
}
