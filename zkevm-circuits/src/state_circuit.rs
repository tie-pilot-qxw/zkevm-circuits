use crate::table::{FixedTable, StackTable};
use crate::util::{self, SubCircuit, SubCircuitConfig};
use crate::witness::Witness;
use eth_types::Field;

use crate::witness::state::{Row, Tag};
//use gadgets::binary_number::BinaryNumberConfig;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
//use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
//use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct StateCircuitConfig<F> {
    q_enable: Selector,
    tag: BinaryNumberConfig<Tag, 4>,
    stamp: Column<Advice>,
    value_hi: Column<Advice>,
    value_lo: Column<Advice>,
    call_id_contract_addr: Column<Advice>,
    pointer_hi: Column<Advice>,
    pointer: Column<Advice>,
    is_write: Column<Advice>,
    _marker: PhantomData<F>,
}

pub struct StateCircuitConfigArgs {
    pub(crate) stack_table: StackTable,
    pub(crate) fixed_table: FixedTable,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            stack_table,
            fixed_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable: Selector = meta.complex_selector();
        let stamp: Column<Advice> = meta.advice_column();
        let value_hi: Column<Advice> = meta.advice_column();
        let value_lo: Column<Advice> = meta.advice_column();
        let call_id_contract_addr: Column<Advice> = meta.advice_column();
        let pointer_hi: Column<Advice> = meta.advice_column();
        let pointer: Column<Advice> = meta.advice_column();
        let is_write: Column<Advice> = meta.advice_column();
        let tag: BinaryNumberConfig<Tag, 4> =
            BinaryNumberChip::configure(meta, q_enable.clone(), None);

        let config: StateCircuitConfig<F> = Self {
            q_enable,
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer,
            is_write,
            _marker: PhantomData,
        };
        //constraints
        //meta.create_gate(name: "State Circuit Common", constraints: |meta|
        // let q_enable = meta.query_selector(config.q_enable);)
        config
    }
}

#[derive(Clone, Default, Debug)]
pub struct StateCircuit<F: Field> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for StateCircuit<F> {
    type Config = StateCircuitConfig<F>;

    fn new_from_witness(witness: &Witness) -> Self {
        StateCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        mut layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        // let tag = BinaryNumberChip::construct(config.tag);
        layouter.assign_region(
            || "state circuit",
            |mut region| {
                region.name_column(|| "stamp", config.stamp);
                /*
                                for (offset, row) in self.witness.iter().enumerate() {
                                    region.assign_advice(
                                        || "stamp",
                                        config.stamp,
                                        offset,
                                        ||Value::known(F::from_u128(row.stamp.as_u128())),
                                    )?;
                                    region.assign_advice(
                                        || "value_hi",
                                        config.value_hi,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.value_hi.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                    region.assign_advice(
                                        || "value_lo",
                                        config.value_lo,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.value_lo.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                    region.assign_advice(
                                        || "call_id_contract_addr",
                                        config.call_id_contract_addr,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.call_id_contract_addr.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                    region.assign_advice(
                                        || "pointer_hi",
                                        config.pointer_hi,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.pointer_hi.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                    region.assign_advice(
                                        || "pointer",
                                        config.pointer,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.pointer.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                    region.assign_advice(
                                        || "is_write",
                                        config.is_write,
                                        offset,
                                        || {
                                            Value::known(F::from_u128(
                                                row.is_write.unwrap_or_default().as_u128(),
                                            ))
                                        },
                                    )?;
                                }
                */

                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        todo!()
    }

    fn num_rows(witness: &Witness) -> usize {
        todo!()
    }
}
