use crate::table::StackTable;
use crate::util::{assign_row, SubCircuit, SubCircuitConfig};
use crate::witness::Block;
use eth_types::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Advice, Any, Column, ConstraintSystem, Error, Selector};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct StackCircuitConfig<F> {
    stack_table: StackTable,
    q_enable: Selector,
    first_access: Column<Advice>,
    _marker: PhantomData<F>,
}

pub struct StackCircuitConfigArgs {
    pub(crate) stack_table: StackTable,
}

impl<F: Field> SubCircuitConfig<F> for StackCircuitConfig<F> {
    type ConfigArgs = StackCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { stack_table }: Self::ConfigArgs,
    ) -> Self {
        // init columns
        let q_enable = meta.selector();
        let first_access = meta.advice_column();
        Self {
            stack_table,
            q_enable,
            first_access,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> StackCircuitConfig<F> {
    fn columns(&self) -> Vec<Column<Any>> {
        let v = vec![
            self.stack_table.stack_stamp.into(),
            self.stack_table.value.into(),
            self.stack_table.address.into(),
            self.stack_table.is_write.into(),
            self.first_access.into(),
        ];
        v
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
        layouter.assign_region(
            || "bytecode circuit",
            |mut region| {
                // annotate col
                region.name_column(|| "stack stamp", config.stack_table.stack_stamp);
                region.name_column(|| "value", config.stack_table.value);
                region.name_column(|| "address", config.stack_table.address);
                region.name_column(|| "is write", config.stack_table.is_write);
                region.name_column(|| "first access", config.first_access);

                for (offset, (witness, selector)) in self
                    .block
                    .witness_table
                    .stack_circuit()
                    .into_iter()
                    .enumerate()
                {
                    if 1 != selector.len() {
                        return Err(Error::Synthesis);
                    }
                    let idx = 0;
                    if selector[idx] {
                        config.q_enable.enable(&mut region, offset)?;
                    }
                    let columns = config.columns();

                    assign_row(&mut region, offset, witness, columns)?;
                }
                Ok(())
            },
        )
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
