mod execution;
mod opcode;

use crate::core_circuit::execution::ExecutionGadgets;
use crate::table::{BytecodeTable, StackTable};
use crate::util::Expr;
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::{assign_column_value, witness::Block};
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const OPERAND_NUM: usize = 3;
const EXECUTION_STATE_NUM: usize = 256;

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
        let operand_stack_stamp = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand_stack_pointer = [(); OPERAND_NUM]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let operand_stack_is_write = [(); OPERAND_NUM]
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
                    "second row program counter = 1",
                    q_step_first * (1u8.expr() - program_counter),
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
            bool_checks.push(("sum 1", q_enable * (sum - 1u8.expr())));
            bool_checks
            // vec![("sum 1", q_step_first_not * (sum - 1u8.expr()))]
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

// impl<F: Field> CoreCircuitConfig<F> {
//     pub fn configure(
//         meta: &mut ConstraintSystem<F>,
//         stack_table: StackTable,
//         bytecode_table: BytecodeTable,
//     ) -> Self {
//         todo!()
//     }
// }

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

                // assign first row
                config.q_step_first.enable(&mut region, 0)?;
                assign_column_value!(region, assign_advice, config, program_counter, 0, 0);
                assign_column_value!(region, assign_advice, config, is_push, 0, 0);
                assign_column_value!(region, assign_advice, config, opcode, 0, 0);
                assign_column_value!(region, assign_advice, config, stack_stamp, 0, 0);
                assign_column_value!(region, assign_advice, config, stack_pointer, 0, 0);
                // assaign second row
                config.q_enable.enable(&mut region, 1)?;
                assign_column_value!(region, assign_advice, config, program_counter, 1, 1);
                assign_column_value!(region, assign_advice, config, is_push, 1, 1);
                assign_column_value!(region, assign_advice, config, opcode, 1, 0x60);
                assign_column_value!(region, assign_advice, config, stack_stamp, 1, 1);
                assign_column_value!(region, assign_advice, config, stack_pointer, 1, 1);
                assign_column_value!(region, assign_advice, config.operand[0], 1, 0xff);
                assign_column_value!(
                    region,
                    assign_advice,
                    config.operand_stack_is_write[0],
                    1,
                    1
                );
                assign_column_value!(region, assign_advice, config.operand_stack_stamp[0], 1, 1);
                assign_column_value!(region, assign_advice, config.operand_stack_pointer[0], 1, 1);
                assign_column_value!(region, assign_advice, config.operand[1], 1, 0);
                assign_column_value!(
                    region,
                    assign_advice,
                    config.operand_stack_is_write[1],
                    1,
                    0
                );
                assign_column_value!(region, assign_advice, config.operand_stack_stamp[1], 1, 0);
                assign_column_value!(region, assign_advice, config.operand_stack_pointer[1], 1, 0);
                assign_column_value!(region, assign_advice, config.operand[2], 1, 0);
                assign_column_value!(
                    region,
                    assign_advice,
                    config.operand_stack_is_write[2],
                    1,
                    0
                );
                assign_column_value!(region, assign_advice, config.operand_stack_stamp[2], 1, 0);
                assign_column_value!(region, assign_advice, config.operand_stack_pointer[2], 1, 0);
                for idx in 0..EXECUTION_STATE_NUM {
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.execution_state_selector[idx],
                        1,
                        0
                    );
                }
                assign_column_value!(
                    region,
                    assign_advice,
                    config.execution_state_selector[0x60],
                    1,
                    1
                ); //PUSH should be 1
                   // assaign second row
                config.q_enable.enable(&mut region, 2)?;
                assign_column_value!(region, assign_advice, config, program_counter, 2, 3);
                assign_column_value!(region, assign_advice, config, is_push, 2, 0);
                assign_column_value!(region, assign_advice, config, opcode, 2, 0x00);
                assign_column_value!(region, assign_advice, config, stack_stamp, 2, 0);
                assign_column_value!(region, assign_advice, config, stack_pointer, 2, 0);
                for idx in 0..OPERAND_NUM {
                    assign_column_value!(region, assign_advice, config.operand[idx], 2, 0);
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.operand_stack_is_write[idx],
                        2,
                        0
                    );
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.operand_stack_stamp[idx],
                        2,
                        0
                    );
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.operand_stack_pointer[idx],
                        2,
                        0
                    );
                }
                for idx in 0..EXECUTION_STATE_NUM {
                    assign_column_value!(
                        region,
                        assign_advice,
                        config.execution_state_selector[idx],
                        2,
                        0
                    );
                }
                assign_column_value!(
                    region,
                    assign_advice,
                    config.execution_state_selector[0x00],
                    2,
                    1
                ); //STOP should be 1
                assign_column_value!(region, assign_advice, config, program_counter, 3, 0);

                Ok(())
            },
        )
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}
// We don't need circuit impl, we need sub circuit impl
// impl<F: Field> Circuit<F> for CoreCircuit<F> {
//     type Config = CoreCircuitConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;
//
//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }
//
//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         let stack_table = StackTable::construct(meta);
//         let bytecode_table = BytecodeTable::construct(meta); //should share with bytecode circuit
//         Self::Config::configure(meta, stack_table, bytecode_table)
//     }
//
//     fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
//         // config.stack_table.assign()
//         todo!()
//     }
// }
