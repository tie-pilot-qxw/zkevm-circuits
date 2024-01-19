pub(crate) mod add;
pub(crate) mod div_mod;
pub(crate) mod length;
pub(crate) mod mul;
pub(crate) mod mulmod;
pub(crate) mod slt_sgt;
pub(crate) mod sub;
pub(crate) mod u64overflow;

use crate::arithmetic_circuit::ArithmeticCircuitConfig;
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::util::{expr_from_u16s, split_u256_hi_lo, split_u256_limb64};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

/// Get all operation gadgets by using this
macro_rules! get_every_operation_gadgets {
    () => {{
        vec![
            crate::arithmetic_circuit::operation::add::new(),
            crate::arithmetic_circuit::operation::sub::new(),
            crate::arithmetic_circuit::operation::mul::new(),
            crate::arithmetic_circuit::operation::slt_sgt::new(),
            crate::arithmetic_circuit::operation::div_mod::new(),
            crate::arithmetic_circuit::operation::length::new(),
            crate::arithmetic_circuit::operation::mulmod::new(),
            crate::arithmetic_circuit::operation::u64overflow::new(),
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
        tag,
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

/// Get the lt_operations between two U256 numbers
/// Supports the following constraint calculations:
/// 1.`c_lo - b_lo = diff_lo - carry_lo << N_BYTES`
/// 2.`c_hi - b_hi - carry_lo = diff_hi - carry_hi << N_BYTES`
fn get_lt_word_operations(operands: Vec<U256>) -> (Vec<bool>, [U256; 2], [Vec<u16>; 2]) {
    assert_eq!(2, operands.len());
    let c = split_u256_hi_lo(&operands[0]);
    let b = split_u256_hi_lo(&operands[1]);
    let (diff, carry_hi) = operands[0].overflowing_sub(operands[1]);
    let (_, carry_lo) = c[1].overflowing_sub(b[1]);
    let mut diff_u16s: Vec<u16> = diff
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, diff_u16s.len());
    let diff_split = split_u256_hi_lo(&diff);
    let diff_u16s_hi = diff_u16s.split_off(8);
    (
        vec![carry_hi, carry_lo],
        diff_split,
        [diff_u16s_hi, diff_u16s],
    )
}

/// Get the lt_operations between two U128 numbers
/// Supports the following constraint calculations:
/// `lhs - rhs = diff - lt * range`
/// Determine whether the operand is positive or negative
fn get_lt_operations(lhs: &U256, rhs: &U256, range: &U256) -> (bool, U256, Vec<u16>) {
    let lt = lhs < rhs;

    let diff = if lt { range - rhs + lhs } else { lhs - rhs };

    let mut diff_u16s: Vec<u16> = diff
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, diff_u16s.len());
    let _ = diff_u16s.split_off(8);

    (lt, diff, diff_u16s)
}

/// `(a * b) / n = k (r) r` --> return k, r
/// or `a / b = k (r) r` --> return k, r
/// input a, b, n, or b is zero
fn get_div_mod(operands: Vec<U256>, is_u256: bool) -> (U256, U256) {
    assert_eq!(operands.len(), 3);
    let (k, r) = if operands[2] == U256::zero() {
        (U256::zero(), U256::zero())
    } else if is_u256 {
        operands[0].div_mod(operands[2])
    } else {
        // 1. k is 256-bit:
        // `a_remainder < n` -> `a_remainder / n <= 1`;
        // `b/n`  is 0-256 bit, so k2 is 0-256 bit
        // 2. r < n, 0-256 bit
        let prod = operands[0].full_mul(operands[1]);
        (
            U256::try_from(prod / operands[2]).unwrap(),
            U256::try_from(prod % operands[2]).unwrap(),
        )
    };
    (k, r)
}

/// a * b = e * d << 256 -> return e, d
/// a, b is 256-bit
/// MulMod contains two muladd512. Extracting mul512 can only perform one multiplication.
fn get_mul512(operands: Vec<U256>) -> (U256, U256) {
    assert_eq!(operands.len(), 2);
    let prod = operands[0].full_mul(operands[1]);
    let mut prod_bytes = [0u8; 64];
    prod.to_little_endian(&mut prod_bytes);
    let e = U256::from_little_endian(&prod_bytes[0..32]);
    let d = U256::from_little_endian(&prod_bytes[32..64]);
    (e, d)
}

/// `a * b + c = d` --> k1_carry_hi, k1_carry_lo
/// The maximum result is 256-bit
/// Use limbs calculation multiplication operations to calculate carry_lo and carry_hi,
/// focusing only on the 256-bit result.
fn get_mul_add(operands: Vec<U256>) -> Vec<U256> {
    assert_eq!(4, operands.len());
    let a_limbs = split_u256_limb64(&operands[0]);
    let b_limbs = split_u256_limb64(&operands[1]);
    let c_split = split_u256_hi_lo(&operands[2]);
    let d_split = split_u256_hi_lo(&operands[3]);

    let t0 = a_limbs[0] * b_limbs[0];
    let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
    let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
    let t3 = a_limbs[0] * b_limbs[3]
        + a_limbs[1] * b_limbs[2]
        + a_limbs[2] * b_limbs[1]
        + a_limbs[3] * b_limbs[0];

    let k1_carry_lo = (t0 + (t1 << 64) + c_split[1]).saturating_sub(d_split[1]) >> 128;
    let k1_carry_hi =
        (t2 + (t3 << 64) + c_split[0] + k1_carry_lo).saturating_sub(d_split[0]) >> 128;

    vec![k1_carry_hi, k1_carry_lo]
}

/// a * b + c = e + d * 2^256 --> return carry_0, carry_1, carry_2
/// The maximum result is 512-bit
/// Use limbs calculation multiplication operations to calculate carry_0, carry_1 and carry_2,
/// focusing only on the 512-bit result.
fn get_mul_add_word(operands: Vec<U256>) -> (U256, U256, U256) {
    assert_eq!(operands.len(), 5);
    let e = operands[3];
    let d = operands[4];
    let e_split = split_u256_hi_lo(&e);
    let d_split = split_u256_hi_lo(&d);
    let c_split = split_u256_hi_lo(&operands[2]);

    let a_limbs = split_u256_limb64(&operands[0]);
    let b_limbs = split_u256_limb64(&operands[1]);
    let t0 = a_limbs[0] * b_limbs[0];
    let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
    let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
    let t3 = a_limbs[0] * b_limbs[3]
        + a_limbs[1] * b_limbs[2]
        + a_limbs[2] * b_limbs[1]
        + a_limbs[3] * b_limbs[0];
    let t4 = a_limbs[1] * b_limbs[3] + a_limbs[2] * b_limbs[2] + a_limbs[3] * b_limbs[1];
    let t5 = a_limbs[2] * b_limbs[3] + a_limbs[3] * b_limbs[2];

    let carry_0 = (t0 + (t1 << 64) + c_split[1]).saturating_sub(e_split[1]) >> 128;
    let carry_1 = (t2 + (t3 << 64) + c_split[0] + carry_0).saturating_sub(e_split[0]) >> 128;
    let carry_2 = (t4 + (t5 << 64) + carry_1).saturating_sub(d_split[1]) >> 128;

    (carry_0, carry_1, carry_2)
}

/// return u16s hi and lo.
/// Inorder to optimize the code rows.
/// When this function is called multiple times, the effect is significant.
fn get_u16s_hi_lo(operands: U256) -> (Vec<u16>, Vec<u16>) {
    let mut lo_u16s: Vec<u16> = operands
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, lo_u16s.len());
    let hi_u16s = lo_u16s.split_off(8);
    (hi_u16s, lo_u16s)
}
