use crate::table::StackTable;
use halo2_proofs::plonk::{Advice, Column};

pub struct StackCircuitConfig<F> {
    stack_table: StackTable,
    first_access: Column<Advice>,
}
