use crate::table::BytecodeTable;
use crate::util::{self, SubCircuitConfig};
use crate::util::{Expr, SubCircuit};
use crate::witness::block::{BytecodeWitness, SelectorColumn};
use crate::witness::Block;
use eth_types::evm_types::OpcodeId::PUSH1;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;

use std::marker::PhantomData;

#[derive(Clone)]
pub struct BytecodeCircuitConfig<F> {
    _marker: PhantomData<F>,
}

pub struct BytecodeCircuitConfigArgs {
    pub(crate) bytecode_table: BytecodeTable,
}

impl<F: Field> SubCircuitConfig<F> for BytecodeCircuitConfig<F> {
    type ConfigArgs = BytecodeCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { bytecode_table }: Self::ConfigArgs,
    ) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field> {
    block: Block<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for BytecodeCircuit<F> {
    type Config = BytecodeCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        BytecodeCircuit {
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
        layouter.assign_region(|| "bytecode circuit", |mut region| Ok(()))
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
