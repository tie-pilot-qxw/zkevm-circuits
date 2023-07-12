pub(crate) mod add;

use crate::arithmetic_circuit::ArithmeticCircuitConfig;
use crate::witness::arithmetic::Tag;
use eth_types::Field;
use halo2_proofs::plonk::{Expression, VirtualCells};

type OperationConfig<F> = ArithmeticCircuitConfig<F>;

pub(crate) trait OperationGadget<F: Field> {
    const NAME: &'static str;
    const TAG: Tag;
    const NUM_ROW: usize;

    fn constraints(
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(&'static str, Expression<F>)>;
}
