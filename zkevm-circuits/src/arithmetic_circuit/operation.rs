pub(crate) mod add;

use crate::arithmetic_circuit::ArithmeticCircuitConfig;
use crate::witness::arithmetic::Tag;
use eth_types::Field;
use halo2_proofs::plonk::{Expression, VirtualCells};

/// Get all operation gadgets by using this
macro_rules! get_every_operation_gadgets {
    () => {{
        vec![crate::arithmetic_circuit::operation::add::new()]
    }};
}
pub(crate) use get_every_operation_gadgets;

type OperationConfig<F> = ArithmeticCircuitConfig<F>;

pub(crate) trait OperationGadget<F: Field> {
    fn name(&self) -> &'static str;
    fn tag(&self) -> Tag;
    /// Number of rows this execution state will use in core circuit
    fn num_row(&self) -> usize;
    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows(&self) -> (usize, usize);
    /// Get gate constraints for this operation (without condition).
    /// Rotation::cur() in the constraints means the row that column config.cnt is 0
    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)>;
}
