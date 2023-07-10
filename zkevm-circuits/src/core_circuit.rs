mod execution;
mod opcode;

use crate::core_circuit::execution::ExecutionGadgets;
use crate::table::{BytecodeTable, StackTable};
use crate::util::{self};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::block::{CoreCircuitWitness, SelectorColumn};
use crate::witness::Block;
use crate::witness::{EXECUTION_STATE_NUM, OPERAND_NUM};
use eth_types::Field;
use gadgets::dynamic_selector::{DynamicSelectorChip, DynamicSelectorConfig};
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CoreCircuitConfig<F> {
    _marker: PhantomData<F>,
}

pub struct CoreCircuitConfigArgs {
    pub(crate) stack_table: StackTable,
    pub(crate) bytecode_table: BytecodeTable,
}

impl<F: Field> SubCircuitConfig<F> for CoreCircuitConfig<F> {
    type ConfigArgs = CoreCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            stack_table,
            bytecode_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let config = Self {
            _marker: PhantomData,
        };

        config
    }
}

#[derive(Clone, Default, Debug)]
pub struct CoreCircuit<F: Field> {
    block: Block<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for CoreCircuit<F> {
    type Config = CoreCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        CoreCircuit {
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
        layouter.assign_region(|| "core circuit", |mut region| Ok(()))
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
