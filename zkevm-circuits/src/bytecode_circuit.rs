use halo2_proofs::plonk::{Advice, Column};
use crate::table::BytecodeTable;

pub struct BytecodeCircuitConfig<F> {
    bytecode_table: BytecodeTable,
}
