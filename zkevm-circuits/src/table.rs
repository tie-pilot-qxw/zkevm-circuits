use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
use halo2curves::group::ff::Field;

/// The table shared between Core Circuit and Stack Circuit
#[derive(Clone, Copy, Debug)]
pub struct StackTable {
    pub stack_stamp: Column<Advice>,
    pub value: Column<Advice>,
    pub is_write: Column<Advice>,
    pub address: Column<Advice>,
}

impl StackTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            stack_stamp: meta.advice_column(),
            value: meta.advice_column(),
            is_write: meta.advice_column(),
            address: meta.advice_column(),
        }
    }

    pub fn assign<F: Field>(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _the_values: Value<F>,
    ) -> Result<(), Error> {
        todo!();
        panic!("see region.assign_advice")
    }
}
/// The table shared between Core Circuit and Bytecode Circuit
#[derive(Clone, Copy, Debug)]
pub struct BytecodeTable {
    pub program_counter: Column<Advice>,
    pub byte: Column<Advice>,
    pub is_push: Column<Advice>,
    pub value_pushed: Column<Advice>,
}

impl BytecodeTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            program_counter: meta.advice_column(),
            byte: meta.advice_column(),
            is_push: meta.advice_column(),
            value_pushed: meta.advice_column(),
        }
    }

    pub fn assign() {
        todo!()
    }
}
