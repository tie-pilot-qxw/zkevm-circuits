use crate::table::{FixedTable, StackTable};
use crate::util::{self, SubCircuit, SubCircuitConfig};
use crate::witness::block::{SelectorColumn, StackCircuitWitness};
use crate::witness::Block;
use eth_types::Field;
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct StackCircuitConfig<F> {
    _marker: PhantomData<F>,
}

pub struct StackCircuitConfigArgs {
    pub(crate) stack_table: StackTable,
    pub(crate) fixed_table: FixedTable,
}

impl<F: Field> SubCircuitConfig<F> for StackCircuitConfig<F> {
    type ConfigArgs = StackCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            stack_table,
            fixed_table,
        }: Self::ConfigArgs,
    ) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct StackCircuit<F: Field> {
    block: Block<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for StackCircuit<F> {
    type Config = StackCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        StackCircuit {
            block: block.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(|| "stack circuit", |mut region| Ok(()))
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
