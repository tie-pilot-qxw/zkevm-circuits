//! SimpleMulGadget gadget
use crate::util::pow_of_two;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Construct the gadget that checks a * b + c == d (modulo 2**256),
/// where a, b, c, d are 256-bit words.
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3
///   t0 = a0 * b0, contribute to 0 ~ 128 bit
///   t1 = a0 * b1 + a1 * b0, contribute to 64 ~ 193 bit (include the carry)
///   t2 = a0 * b2 + a2 * b0 + a1 * b1, contribute to above 128 bit
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, contribute to above 192 bit
///
/// Finally we have:
///  t0 + t1 << 64 + c_lo - d_lo = carry_lo << 128
///  t2 + t3 << 64 + c_hi + carry_lo - d_hi = carry_hi << 128
#[derive(Clone, Debug)]
pub struct SimpleMulGadget<F> {
    a: [Expression<F>; 4],
    b: [Expression<F>; 4],
    c: [Expression<F>; 2],
    d: [Expression<F>; 2],
    carry: [Expression<F>; 2],
}

impl<F: Field> SimpleMulGadget<F> {
    /// Return SimpleMulGadget
    pub fn new(
        a: [Expression<F>; 4],
        b: [Expression<F>; 4],
        c: [Expression<F>; 2],
        d: [Expression<F>; 2],
        carry: [Expression<F>; 2],
    ) -> Self {
        Self { a, b, c, d, carry }
    }

    /// Return SimpleMulGadget constraints
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let mut res: Vec<(String, Expression<F>)> = Vec::new();
        let t0 = self.a[0].clone() * self.b[0].clone();
        let t1 = self.a[0].clone() * self.b[1].clone() + self.a[1].clone() * self.b[0].clone();
        let t2 = self.a[0].clone() * self.b[2].clone()
            + self.a[1].clone() * self.b[1].clone()
            + self.a[2].clone() * self.b[0].clone();
        let t3 = self.a[0].clone() * self.b[3].clone()
            + self.a[1].clone() * self.b[2].clone()
            + self.a[2].clone() * self.b[1].clone()
            + self.a[3].clone() * self.b[0].clone();

        res.push((
            "t0 + t1 * 2^64 + c_lo = d_lo + carry_lo * 2^128".to_string(),
            t0.clone() + t1.clone() * pow_of_two::<F>(64) + self.c[0].clone()
                - (self.d[0].clone() + self.carry[0].clone() * pow_of_two::<F>(128)),
        ));

        res.push((
            "t2 + t3 * 2^64 + c_hi + carry_lo = d_hi + carry_hi * 2^128".to_string(),
            t2.clone()
                + t3.clone() * pow_of_two::<F>(64)
                + self.c[1].clone()
                + self.carry[0].clone()
                - (self.d[1].clone() + self.carry[1].clone() * pow_of_two::<F>(128)),
        ));

        res
    }
}
