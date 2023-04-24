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
    stack_table: StackTable,
    fixed_table: FixedTable,
    q_step_first: Selector,
    q_enable: Selector,
    address_diff_inv: Column<Advice>, //used for first_access
    first_access: IsZeroConfig<F>,
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
        // init columns
        let q_step_first = meta.selector();
        let q_enable = meta.complex_selector();
        let address_diff_inv = meta.advice_column();
        let not_first_access = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let address_prev = meta.query_advice(stack_table.address, Rotation::prev());
                let address = meta.query_advice(stack_table.address, Rotation::cur());
                address - address_prev
            },
            address_diff_inv,
        );
        meta.create_gate("init constraints", |meta| {
            let q_step_first = meta.query_selector(q_step_first);
            let stamp = meta.query_advice(stack_table.stack_stamp, Rotation::cur());
            let value = meta.query_advice(stack_table.value, Rotation::cur());
            let address = meta.query_advice(stack_table.address, Rotation::cur());
            let is_write = meta.query_advice(stack_table.is_write, Rotation::cur());
            vec![
                ("init stamp = 0", q_step_first.clone() * stamp),
                ("init pointer = 0", q_step_first.clone() * value),
                ("init address = 0", q_step_first.clone() * address),
                ("init is write = 0", q_step_first.clone() * is_write),
            ]
        });
        meta.create_gate("is write", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let first_access = 1u8.expr() - not_first_access.expr();
            let is_write = meta.query_advice(stack_table.is_write, Rotation::cur());
            vec![(
                "stack first access is write",
                q_enable * first_access * (1u8.expr() - is_write),
            )]
        });
        meta.create_gate("value consistency", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let is_write = meta.query_advice(stack_table.is_write, Rotation::cur());
            let value_prev = meta.query_advice(stack_table.value, Rotation::prev());
            let value = meta.query_advice(stack_table.value, Rotation::cur());
            let not_first_access = not_first_access.expr();
            vec![(
                "read value equals prev value except first access",
                q_enable * not_first_access * (1u8.expr() - is_write) * (value - value_prev),
            )]
        });
        meta.create_gate("cur-prev address", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let address_prev = meta.query_advice(stack_table.address, Rotation::prev());
            let address = meta.query_advice(stack_table.address, Rotation::cur());
            vec![(
                "cur-prev address is zero or one",
                q_enable
                    * (address.clone() - address_prev.clone())
                    * (address - address_prev - 1u8.expr()),
            )]
        });
        /*
        meta.lookup_any(
            "address is increasing", //todo use u10 since stack address <=1024
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let address_prev = meta.query_advice(stack_table.address, Rotation::prev());
                let address = meta.query_advice(stack_table.address, Rotation::cur());
                let u8 = meta.query_fixed(fixed_table.u8, Rotation::cur());
                vec![(q_enable * (address - address_prev), u8)]
            },
        );

         */
        meta.lookup_any(
            "stamp is increasing except first access (temporary solution, diff is in [0, 255])",
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let stamp_prev = meta.query_advice(stack_table.stack_stamp, Rotation::prev());
                let stamp = meta.query_advice(stack_table.stack_stamp, Rotation::cur());
                let u8 = meta.query_fixed(fixed_table.u8, Rotation::cur());
                let not_first_access = not_first_access.expr();
                vec![(
                    q_enable * not_first_access * (stamp - stamp_prev - 1u8.expr()),
                    u8,
                )]
            },
        );

        Self {
            stack_table,
            fixed_table,
            q_enable,
            q_step_first,
            address_diff_inv,
            first_access: not_first_access,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> StackCircuitConfig<F> {
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        witness: &StackCircuitWitness,
        offset: usize,
    ) -> Result<(), Error> {
        util::assign_cell(
            region,
            offset,
            witness.stack_table_stamp,
            self.stack_table.stack_stamp.into(),
        )?;
        util::assign_cell(
            region,
            offset,
            witness.stack_table_address,
            self.stack_table.address.into(),
        )?;
        util::assign_cell(
            region,
            offset,
            witness.stack_table_value,
            self.stack_table.value.into(),
        )?;
        util::assign_cell(
            region,
            offset,
            witness.stack_table_is_write,
            self.stack_table.is_write.into(),
        )?;
        Ok(())
    }

    fn assign_selector(
        &self,
        region: &mut Region<'_, F>,
        selector: &SelectorColumn,
        offset: usize,
    ) -> Result<(), Error> {
        if selector.stack_q_enable {
            self.q_enable.enable(region, offset)?;
        }
        Ok(())
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
        config.fixed_table.load(layouter)?;
        layouter.assign_region(
            || "stack circuit",
            |mut region| {
                // annotate col
                region.name_column(|| "stack stamp", config.stack_table.stack_stamp);
                region.name_column(|| "value", config.stack_table.value);
                region.name_column(|| "address", config.stack_table.address);
                region.name_column(|| "is write", config.stack_table.is_write);
                region.name_column(|| "address diff inv", config.address_diff_inv);

                let first_access = IsZeroChip::construct(config.first_access.clone());

                for (offset, witness) in self.block.witness_table.stack.iter().enumerate() {
                    config.assign_row(&mut region, witness, offset)?;
                    // let columns = config.columns();
                    // assign_row(&mut region, i, witness, columns)?;
                }
                for (offset, selector) in self.block.witness_table.selector.iter().enumerate() {
                    config.assign_selector(&mut region, selector, offset)?;
                }
                let stack = &self.block.witness_table.stack;
                for offset in 0..(stack.len() - 1) {
                    let cur_addr = stack[offset].stack_table_address.unwrap();
                    let next_addr = stack[offset + 1].stack_table_address.unwrap();
                    first_access.assign(
                        &mut region,
                        offset + 1,
                        Value::known(F::from(next_addr) - F::from(cur_addr)),
                    )?;
                }

                // enable step first
                config.q_step_first.enable(&mut region, 0)?;
                Ok(())
            },
        )
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
