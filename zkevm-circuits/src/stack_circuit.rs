use halo2_proofs::plonk::{Advice, Column};
use crate::table::StackTable;

pub struct StackCircuitConfig<F> {
    stack_table: StackTable,
    first_access: [Column<Advice>; 5],
}