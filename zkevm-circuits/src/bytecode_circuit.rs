use crate::assign_column_value;
use crate::table::BytecodeTable;
use crate::util::SubCircuitConfig;
use crate::util::{Expr, SubCircuit};
use eth_types::evm_types::OpcodeId::PUSH1;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use halo2curves::bn256::Fr;
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

        meta.create_gate("Cur-Prev program counter", |meta| {
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

#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for BytecodeCircuit<F> {
    type Config = BytecodeCircuitConfig<F>;

    fn new_from_block() -> Self {
        BytecodeCircuit {
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

                assign_column_value!(
                    region,
                    assign_advice,
                    config.bytecode_table,
                    program_counter,
                    0,
                    0
                );
                for offset in 1..3 {
                    config.q_enable.enable(&mut region, offset)?;
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.bytecode_table,
                        program_counter,
                        offset,
                        offset
                    );
                }
                assign_column_value!(region, assign_advice, config.bytecode_table, byte, 1, 0x60);
                assign_column_value!(region, assign_advice, config.bytecode_table, byte, 2, 0xff);
                // padding is necessary for byte at last row +1
                assign_column_value!(region, assign_advice, config.bytecode_table, byte, 3, 0);
                assign_column_value!(region, assign_advice, config.bytecode_table, is_push, 1, 1);
                assign_column_value!(region, assign_advice, config.bytecode_table, is_push, 2, 0);
                assign_column_value!(
                    region,
                    assign_advice,
                    config.bytecode_table,
                    value_pushed,
                    1,
                    0xff
                );
                assign_column_value!(
                    region,
                    assign_advice,
                    config.bytecode_table,
                    value_pushed,
                    2,
                    0
                );
                Ok(())
            },
        )
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
