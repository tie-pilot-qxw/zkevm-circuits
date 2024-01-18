use crate::arithmetic_circuit::operation::{OperationConfig, OperationGadget};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256};
use halo2_proofs::plonk::{Expression, VirtualCells};
use std::marker::PhantomData;

pub(crate) struct LengthGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for LengthGadget<F> {
    fn name(&self) -> &'static str {
        "LENGTH"
    }

    fn tag(&self) -> Tag {
        Tag::Length
    }

    fn num_row(&self) -> usize {
        2 // TODO: change it
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (1, 0)
    }

    fn get_constraints(
        &self,
        _config: &OperationConfig<F>,
        _meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        vec![]
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(_operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    (vec![], vec![])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(LengthGadget(PhantomData))
}

#[cfg(test)]
mod test {
    #[test]
    fn test_gen_witness() {}
}
