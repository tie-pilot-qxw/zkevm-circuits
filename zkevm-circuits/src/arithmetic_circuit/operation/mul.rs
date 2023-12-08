use crate::arithmetic_circuit::operation::{OperationConfig, OperationGadget};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToBigEndian, ToLittleEndian, U256};
use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct AddGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for AddGadget<F> {
    fn name(&self) -> &'static str {
        "MUL"
    }

    fn tag(&self) -> Tag {
        Tag::Mul
    }

    fn num_row(&self) -> usize {
        6
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (6, 1)
    }

    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        constraints
    }
}

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(2, operands.len());

    (vec![], vec![])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(AddGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;
    use gadgets::util::{expr_from_u16s, pow_of_two, split_u256_hi_lo, Expr};
    #[ignore = "remove ignore after arithmetic is finished"]
    #[test]
    fn test_gen_witness() {
        let a = 3.into();
        let b = u128::MAX.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();

        assert_eq!(a + b, result[0]);
        assert_eq!(U256::from(1), result[1]);
        // assert_eq!(arithmetic[0].operand_0_hi,u16_sum_for_c_hi)
    }
}
