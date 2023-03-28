use crate::table::StackTable;
use halo2_proofs::plonk::{Advice, Column};
use std::marker::PhantomData;

pub struct StackCircuitConfig<F> {
    stack_table: StackTable,
    first_access: Column<Advice>,
    phantom: PhantomData<F>,
}
