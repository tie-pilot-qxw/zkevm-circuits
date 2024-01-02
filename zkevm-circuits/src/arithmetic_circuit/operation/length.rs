use crate::arithmetic_circuit::operation::{OperationConfig, OperationGadget};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, U256};
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
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
        0 // TODO: change it
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (1, 0)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        vec![]
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    (vec![], vec![])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(LengthGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;
    #[test]
    fn test_gen_witness() {}
}
