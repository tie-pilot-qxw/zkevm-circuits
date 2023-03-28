use crate::table::BytecodeTable;
use halo2_proofs::plonk::{Advice, Column};
use std::marker::PhantomData;

pub struct BytecodeCircuitConfig<F> {
    bytecode_table: BytecodeTable,
    phantom: PhantomData<F>,
}
