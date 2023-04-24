mod execution;
mod opcode;

use crate::core_circuit::execution::ExecutionGadgets;
use crate::table::{BytecodeTable, StackTable};
use crate::util::{self, Expr};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::block::{CoreCircuitWitness, SelectorColumn};
use crate::witness::Block;
use crate::witness::{EXECUTION_STATE_NUM, OPERAND_NUM};
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CoreCircuitConfig<F> {
    q_step_first: Selector,
    q_enable: Selector, // to avoid apply gate to unusable rows
    program_counter: Column<Advice>,
    opcode: Column<Advice>,
    is_push: Column<Advice>,
    execution_state_selector: [Column<Advice>; EXECUTION_STATE_NUM],
    operand: [Column<Advice>; OPERAND_NUM],
    operand_stack_stamp: [Column<Advice>; OPERAND_NUM],
    operand_stack_pointer: [Column<Advice>; OPERAND_NUM],
    operand_stack_is_write: [Column<Advice>; OPERAND_NUM],
    stack_stamp: Column<Advice>,
    stack_pointer: Column<Advice>,
    // External tables
    stack_table: StackTable,
    bytecode_table: BytecodeTable,
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
        // init columns
        let q_step_first = meta.complex_selector();
        let q_enable = meta.selector();
        let program_counter = meta.advice_column();
        let opcode = meta.advice_column();
        let is_push = meta.advice_column();
        let execution_state_selector: [Column<Advice>; EXECUTION_STATE_NUM] = [();
            EXECUTION_STATE_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand: [Column<Advice>; OPERAND_NUM] = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand_stack_stamp: [Column<Advice>; OPERAND_NUM] = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand_stack_pointer: [Column<Advice>; OPERAND_NUM] = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand_stack_is_write: [Column<Advice>; OPERAND_NUM] = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let stack_stamp = meta.advice_column();
        let stack_pointer = meta.advice_column();

        // add gates here
        meta.create_gate("init constraints", |meta| {
            let q_step_first = meta.query_selector(q_step_first);
            let stack_stamp = meta.query_advice(stack_stamp, Rotation::cur());
            let stack_pointer = meta.query_advice(stack_pointer, Rotation::cur());
            let program_counter = meta.query_advice(program_counter, Rotation::next());
            vec![
                ("init stack stamp = 0", q_step_first.clone() * stack_stamp),
                (
                    "init stack pointer = 0",
                    q_step_first.clone() * stack_pointer,
                ),
                (
                    "second row program counter = 0",
                    q_step_first * program_counter,
                ),
            ]
        });
        meta.create_gate("execution state selector", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let sum = (0..EXECUTION_STATE_NUM)
                .map(|idx| meta.query_advice(execution_state_selector[idx], Rotation::cur()))
                .reduce(|acc, expr| acc + expr)
                .unwrap();
            let mut bool_checks: Vec<(&str, Expression<F>)> = (0..EXECUTION_STATE_NUM)
                .map(|idx| {
                    let x = meta.query_advice(execution_state_selector[idx], Rotation::cur());
                    (
                        "execution state selector should be bool",
                        q_enable.clone() * x.clone() * (1u8.expr() - x),
                    )
                })
                .collect(); //.chain()
                            //only 1 selector actived at one time
            bool_checks.push(("sum 1", q_enable * (sum - 1u8.expr())));
            bool_checks
        });
        meta.lookup_any("opcode lookup in bytecode table", |meta| {
            let program_counter = meta.query_advice(program_counter, Rotation::cur());
            let is_push = meta.query_advice(is_push, Rotation::cur());
            let opcode = meta.query_advice(opcode, Rotation::cur());
            // first operand * is_push means only used for push opcode as value_pushed
            let operand = meta.query_advice(operand[0], Rotation::cur());
            let program_counter_table =
                meta.query_advice(bytecode_table.program_counter, Rotation::cur());
            let is_push_table = meta.query_advice(bytecode_table.is_push, Rotation::cur());
            let byte_table = meta.query_advice(bytecode_table.byte, Rotation::cur());
            let value_pushed_table =
                meta.query_advice(bytecode_table.value_pushed, Rotation::cur());
            vec![
                (program_counter, program_counter_table),
                (is_push.clone(), is_push_table),
                (opcode, byte_table),
                (operand * is_push, value_pushed_table),
            ]
        });
        //todo opcode gadagets configure, don't forget opcode selectors
        meta.lookup_any(
            "(operand 0, operand stack stamp 0, stack pointer 0, is write 0) in stack table",
            |meta| {
                let operand_0 = meta.query_advice(operand[0], Rotation::cur());
                let operand_stack_stamp_0 =
                    meta.query_advice(operand_stack_stamp[0], Rotation::cur());
                let operand_stack_pointer_0 =
                    meta.query_advice(operand_stack_pointer[0], Rotation::cur());
                let operand_is_write_0 =
                    meta.query_advice(operand_stack_is_write[0], Rotation::cur());

                let stack_value_table = meta.query_advice(stack_table.value, Rotation::cur());
                let stack_stamp_table = meta.query_advice(stack_table.stack_stamp, Rotation::cur());
                let stack_pointer_table = meta.query_advice(stack_table.address, Rotation::cur());
                let is_write_table = meta.query_advice(stack_table.is_write, Rotation::cur());

                vec![
                    (operand_0, stack_value_table),
                    (operand_stack_stamp_0, stack_stamp_table),
                    (operand_stack_pointer_0, stack_pointer_table),
                    (operand_is_write_0, is_write_table),
                ]
            },
        );
        meta.lookup_any(
            "(operand 1, operand stack stamp 1, stack pointer 1, is write 1) in stack table",
            |meta| {
                let operand_1 = meta.query_advice(operand[1], Rotation::cur());
                let operand_stack_stamp_1 =
                    meta.query_advice(operand_stack_stamp[1], Rotation::cur());
                let operand_stack_pointer_1 =
                    meta.query_advice(operand_stack_pointer[1], Rotation::cur());
                let operand_is_write_1 =
                    meta.query_advice(operand_stack_is_write[1], Rotation::cur());

                let stack_value_table = meta.query_advice(stack_table.value, Rotation::cur());
                let stack_stamp_table = meta.query_advice(stack_table.stack_stamp, Rotation::cur());
                let stack_pointer_table = meta.query_advice(stack_table.address, Rotation::cur());
                let is_write_table = meta.query_advice(stack_table.is_write, Rotation::cur());

                vec![
                    (operand_1, stack_value_table),
                    (operand_stack_stamp_1, stack_stamp_table),
                    (operand_stack_pointer_1, stack_pointer_table),
                    (operand_is_write_1, is_write_table),
                ]
            },
        );
        meta.lookup_any(
            "(operand 2, operand stack stamp 2, stack pointer 2, is write 2) in stack table",
            |meta| {
                let operand_2 = meta.query_advice(operand[2], Rotation::cur());
                let operand_stack_stamp_2 =
                    meta.query_advice(operand_stack_stamp[2], Rotation::cur());
                let operand_stack_pointer_2 =
                    meta.query_advice(operand_stack_pointer[2], Rotation::cur());
                let operand_is_write_2 =
                    meta.query_advice(operand_stack_is_write[2], Rotation::cur());

                let stack_value_table = meta.query_advice(stack_table.value, Rotation::cur());
                let stack_stamp_table = meta.query_advice(stack_table.stack_stamp, Rotation::cur());
                let stack_pointer_table = meta.query_advice(stack_table.address, Rotation::cur());
                let is_write_table = meta.query_advice(stack_table.is_write, Rotation::cur());

                vec![
                    (operand_2, stack_value_table),
                    (operand_stack_stamp_2, stack_stamp_table),
                    (operand_stack_pointer_2, stack_pointer_table),
                    (operand_is_write_2, is_write_table),
                ]
            },
        );

        let config = Self {
            q_step_first,
            q_enable,
            program_counter,
            opcode,
            is_push,
            execution_state_selector,
            operand,
            operand_stack_stamp,
            operand_stack_pointer,
            operand_stack_is_write,
            stack_stamp,
            stack_pointer,
            stack_table,
            bytecode_table,
            _marker: PhantomData,
        };
        // execution gadgets configure, e.g. opcodes
        ExecutionGadgets::configure(&config, meta);

        config
    }
}

impl<F: Field> CoreCircuitConfig<F> {
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        witness: &CoreCircuitWitness,
        offset: usize,
    ) -> Result<(), Error> {
        util::assign_cell(
            region,
            offset,
            witness.program_counter,
            self.program_counter.into(),
        )?;
        util::assign_cell(region, offset, witness.opcode, self.opcode.into())?;
        util::assign_cell(region, offset, witness.is_push, self.is_push.into())?;
        util::assign_cell(region, offset, witness.stack_stamp, self.stack_stamp.into())?;
        util::assign_cell(
            region,
            offset,
            witness.stack_pointer,
            self.stack_pointer.into(),
        )?;
        for i in 0..OPERAND_NUM {
            util::assign_cell(region, offset, witness.operand[i], self.operand[i].into())?;
            util::assign_cell(
                region,
                offset,
                witness.operand_stack_stamp[i],
                self.operand_stack_stamp[i].into(),
            )?;
            util::assign_cell(
                region,
                offset,
                witness.operand_stack_pointer[i],
                self.operand_stack_pointer[i].into(),
            )?;
            util::assign_cell(
                region,
                offset,
                witness.operand_stack_is_write[i],
                self.operand_stack_is_write[i].into(),
            )?;
        }
        for i in 0..EXECUTION_STATE_NUM {
            util::assign_cell(
                region,
                offset,
                witness.execution_state_selector[i],
                self.execution_state_selector[i].into(),
            )?;
        }
        Ok(())
    }

    fn assign_selector(
        &self,
        region: &mut Region<'_, F>,
        selector: &SelectorColumn,
        offset: usize,
    ) -> Result<(), Error> {
        if selector.core_q_enable {
            self.q_enable.enable(region, offset)?;
        }
        Ok(())
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
        layouter.assign_region(
            || "core circuit",
            |mut region| {
                // annotate col
                region.name_column(|| "program counter", config.program_counter);
                region.name_column(|| "is push", config.is_push);
                region.name_column(|| "opcode", config.opcode);
                region.name_column(|| "stack stamp", config.stack_stamp);
                region.name_column(|| "stack pointer", config.stack_pointer);
                for idx in 0..OPERAND_NUM {
                    region.name_column(|| format!("operand {}", idx), config.operand[idx]);
                    region.name_column(
                        || format!("stack is write {}", idx),
                        config.operand_stack_is_write[idx],
                    );
                    region.name_column(
                        || format!("stack stamp {}", idx),
                        config.operand_stack_stamp[idx],
                    );
                    region.name_column(
                        || format!("stack pointer {}", idx),
                        config.operand_stack_pointer[idx],
                    );
                }
                for idx in 0..EXECUTION_STATE_NUM {
                    region.name_column(
                        || format!("execution state selector {}", idx),
                        config.execution_state_selector[idx],
                    );
                }

                for (offset, witness) in self.block.witness_table.core.iter().enumerate() {
                    config.assign_row(&mut region, witness, offset)?;
                }
                for (offset, selector) in self.block.witness_table.selector.iter().enumerate() {
                    config.assign_selector(&mut region, selector, offset)?;
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
