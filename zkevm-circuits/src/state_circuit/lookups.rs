use std::marker::PhantomData;

use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
pub struct Config {
    u8: Column<Fixed>,
    u10: Column<Fixed>,
    u16: Column<Fixed>,
}

impl Config {
    pub fn range_check_u8<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u8, Rotation::cur()))]
        });
    }

    pub fn range_check_u10<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u10, Rotation::cur()))]
        });
    }

    pub fn range_check_u16<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u16, Rotation::cur()))]
        });
    }
}

pub struct Chip<F: Field> {
    config: Config,
    _market: PhantomData<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config) -> Self {
        Self {
            config,
            _market: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let config = Config {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
        };
        meta.annotate_lookup_any_column(config.u8, || "LOOKUP u8");
        meta.annotate_lookup_any_column(config.u10, || "LOOKUP u10");
        meta.annotate_lookup_any_column(config.u16, || "LOOKUP u16");

        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [
            // (self.config.u8, 8),
            // (self.config.u10, 10),
            (self.config.u16, 16),
        ] {
            layouter.assign_region(
                || format!("assign u{exponent} fixed column"),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {i} in u{exponent} fixed column"),
                            column,
                            i,
                            || Value::known(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        println!("complete lookup assign");
        Ok(())
    }
}
