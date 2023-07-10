use crate::add_expression_to_constraints;
use crate::core_circuit::execution::{ExecutionConfig, ExecutionGadget};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;

use std::marker::PhantomData;
use std::str::FromStr;

pub struct AddGadget<F> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for AddGadget<F> {
    const NAME: &'static str = "ADD";

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        AddGadget {
            _marker: PhantomData,
        }
    }
}
