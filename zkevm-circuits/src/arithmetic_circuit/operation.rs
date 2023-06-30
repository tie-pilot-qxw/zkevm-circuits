pub(crate) mod add;

use crate::arithmetic_circuit::ArithmeticCircuitConfig;
use crate::witness::arithmetic::Tag;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{Expression, VirtualCells};

type OperationConfig<F> = ArithmeticCircuitConfig<F>;

pub(crate) trait OperationGadget<F: FieldExt> {
    const NAME: &'static str;
    const TAG: Tag;
    const ROW_NUM: usize;

    fn constraints(
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(&'static str, Expression<F>)>;
}
