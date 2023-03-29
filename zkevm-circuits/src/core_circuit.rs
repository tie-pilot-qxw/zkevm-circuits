mod opcode;

use crate::table::{BytecodeTable, StackTable};
use crate::util::Expr;
use crate::util::{SubCircuit, SubCircuitConfig};
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const OPERAND_NUM: usize = 3;

#[derive(Clone)]
pub struct CoreCircuitConfig<F> {
    q_step_first: Selector,
    //todo selectors: is_add, is_pop, etc...
    program_counter: Column<Advice>,
    opcode: Column<Advice>,
    is_push: Column<Advice>,
    operand: [Column<Advice>; OPERAND_NUM],
    operand_stack_stamp: [Column<Advice>; OPERAND_NUM],
    operand_stack_pointer: [Column<Advice>; OPERAND_NUM],
    operand_stack_is_write: [Column<Advice>; OPERAND_NUM],
    stack_stamp: Column<Advice>,
    stack_pointer: Column<Advice>,
    // External tables
    stack_table: StackTable,
    bytecode_table: BytecodeTable,
    phantom: PhantomData<F>,
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
        let program_counter = meta.advice_column();
        let opcode = meta.advice_column();
        let is_push = meta.advice_column();
        let operand = [(); OPERAND_NUM]
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
        /*
        meta.create_gate("Init constraints", |meta| {
            let q_step_first = meta.query_selector(q_step_first);
            let stack_stamp = meta.query_advice(stack_stamp, Rotation::cur());
            let stack_pointer = meta.query_advice(stack_pointer, Rotation::cur());
            let program_counter = meta.query_advice(program_counter, Rotation::next());
            vec![
                ("init stack_stamp = 0", q_step_first.clone() * stack_stamp),
                (
                    "init stack_pointer = 0",
                    q_step_first.clone() * stack_pointer,
                ),
                (
                    "second row program counter = 1",
                    q_step_first * (1u8.expr() - program_counter),
                ),
            ]
        });
        meta.create_gate("Cur-Prev stack_stamp constraints", |meta| {
            let q_step_first_not = 1u8.expr() - meta.query_selector(q_step_first);
            let stack_stamp_prev = meta.query_advice(stack_stamp, Rotation::prev());
            let stack_stamp = meta.query_advice(stack_stamp, Rotation::cur());
            vec![(
                "stack_stamp increment",
                q_step_first_not.clone() * (stack_stamp - stack_stamp_prev - 1u8.expr()), //todo should do it based on OPCODE
            )]
        });
        meta.lookup_any("opcode lookup in bytecode table", |meta| {
            let program_counter = meta.query_advice(program_counter, Rotation::cur());
            let program_counter_in_table =
                meta.query_advice(bytecode_table.program_counter, Rotation::cur());
            vec![(program_counter, program_counter_in_table)] // todo add opcode, is_push in lookup; todo pair.0 and pair.1 order?
        });
        */
        //todo opcode gadagets configure, don't forget opcode selectors

        Self {
            q_step_first,
            program_counter,
            opcode,
            is_push,
            operand,
            operand_stack_stamp,
            operand_stack_pointer,
            operand_stack_is_write,
            stack_stamp,
            stack_pointer,
            stack_table,
            bytecode_table,
            phantom: PhantomData,
        }
    }
}

impl<F: Field> CoreCircuitConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        stack_table: StackTable,
        bytecode_table: BytecodeTable,
    ) -> Self {
        todo!()
    }
}

#[derive(Clone, Default, Debug)]
pub struct CoreCircuit<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for CoreCircuit<F> {
    type Config = CoreCircuitConfig<F>;

    fn new_from_block() -> Self {
        CoreCircuit {
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
        todo!()
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
