pub(crate) mod add;
pub(crate) mod length;
pub(crate) mod mul;
pub(crate) mod sub;

use crate::arithmetic_circuit::ArithmeticCircuitConfig;
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256};
use gadgets::util::expr_from_u16s;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

/// Get all operation gadgets by using this
macro_rules! get_every_operation_gadgets {
    () => {{
        vec![
            crate::arithmetic_circuit::operation::add::new(),
            crate::arithmetic_circuit::operation::sub::new(),
            crate::arithmetic_circuit::operation::mul::new(),
            crate::arithmetic_circuit::operation::length::new(),
        ]
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

//create a row of the arithmetic circuit
pub(crate) fn get_row(a: [U256; 2], b: [U256; 2], u16s: Vec<u16>, cnt: u8, tag: Tag) -> Row {
    Row {
        tag: tag,
        cnt: cnt.into(),
        operand_0_hi: a[0],
        operand_0_lo: a[1],
        operand_1_hi: b[0],
        operand_1_lo: b[1],
        u16_0: u16s[0].into(),
        u16_1: u16s[1].into(),
        u16_2: u16s[2].into(),
        u16_3: u16s[3].into(),
        u16_4: u16s[4].into(),
        u16_5: u16s[5].into(),
        u16_6: u16s[6].into(),
        u16_7: u16s[7].into(),
    }
}

//calculate the u16 sum.u16_lo_sum and u16_hi_sum are 64-bit.
pub(crate) fn get_u16s<F: Field>(
    config: &OperationConfig<F>,
    meta: &mut VirtualCells<F>,
    rotation: Rotation,
) -> (Expression<F>, Expression<F>, Expression<F>) {
    let mut u16s: Vec<_> = (0..8).map(|i| config.get_u16(i, rotation)(meta)).collect();
    let u16_sum = expr_from_u16s(&u16s);
    let u16_hi = u16s.split_off(4);
    let u16_lo_sum = expr_from_u16s(&u16s);
    let u16_hi_sum = expr_from_u16s(&u16_hi);
    (u16_sum, u16_lo_sum, u16_hi_sum)
}
