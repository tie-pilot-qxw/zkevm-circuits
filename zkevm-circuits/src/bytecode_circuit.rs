use crate::table::BytecodeTable;
use crate::util::{assign_row, SubCircuitConfig};
use crate::util::{Expr, SubCircuit};
use crate::witness::Block;
use eth_types::evm_types::OpcodeId::PUSH1;
use eth_types::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;

use std::marker::PhantomData;

#[derive(Clone)]
pub struct BytecodeCircuitConfig<F> {
    bytecode_table: BytecodeTable,
    q_enable: Selector,
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
        // init columns
        let q_enable = meta.selector();

        meta.create_gate("cur-prev program counter", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let program_counter =
                meta.query_advice(bytecode_table.program_counter, Rotation::cur());
            let program_counter_prev =
                meta.query_advice(bytecode_table.program_counter, Rotation::prev());
            vec![(
                "program counter increment",
                q_enable * (program_counter - program_counter_prev - 1u8.expr()),
            )]
        });
        meta.create_gate("is push", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let is_push = meta.query_advice(bytecode_table.is_push, Rotation::cur());
            let byte = meta.query_advice(bytecode_table.byte, Rotation::cur());
            let value_pushed = meta.query_advice(bytecode_table.value_pushed, Rotation::cur());
            let byte_next = meta.query_advice(bytecode_table.byte, Rotation::next());
            vec![
                (
                    "is push if byte is push1 ... push32",
                    q_enable.clone() * is_push.clone() * (byte - PUSH1.as_u8().expr()),
                ),
                (
                    "value pushed = next byte if is push",
                    q_enable * is_push * (value_pushed - byte_next),
                ),
            ]
        });
        Self {
            bytecode_table,
            q_enable,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> BytecodeCircuitConfig<F> {
    fn columns(&self) -> Vec<Column<Any>> {
        let v = vec![
            self.bytecode_table.program_counter.into(),
            self.bytecode_table.byte.into(),
            self.bytecode_table.is_push.into(),
            self.bytecode_table.value_pushed.into(),
        ];
        v
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
        layouter.assign_region(
            || "bytecode circuit",
            |mut region| {
                // annotate col
                region.name_column(|| "program counter", config.bytecode_table.program_counter);
                region.name_column(|| "is push", config.bytecode_table.is_push);
                region.name_column(|| "byte", config.bytecode_table.byte);
                region.name_column(|| "value pushed", config.bytecode_table.value_pushed);

                for (offset, (witness, selector)) in self
                    .block
                    .witness_table
                    .bytecode_circuit()
                    .iter()
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
