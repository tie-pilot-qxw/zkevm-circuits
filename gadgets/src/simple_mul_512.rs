// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! SimpleMul512Gadget gadget
use crate::util::pow_of_two;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Construct the gadget that checks a * b + c == d * 2**256 + e
/// where a, b, c, d, e are 256-bit words.
///
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3, t4, t5, t6:
///   t0 = a0 * b0,  0 - 128bit
///   t1 = a0 * b1 + a1 * b0, 64 - 193bit
///   t2 = a0 * b2 + a2 * b0 + a1 * b1, 128 - 258bit
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, 192 - 322bit
///   t4 = a1 * b3 + a2 * b2 + a3 * b1,
///   t5 = a2 * b3 + a3 * b2,
///   t6 = a3 * b3,

/// Finally we just prove:
///   t0 + t1 * 2^64 + c_lo = e_lo + carry_0 * 2^128
///   t2 + t3 * 2^64 + c_hi + carry_0 = e_hi + carry_1 * 2^128
///   t4 + t5 * 2^64 + carry_1 = d_lo + carry_2 * 2^128
///   t6 + carry_2 = d_hi
///
/// The part of carry_0 that contributes more than 128 bits is 65 bits, (129+64)-128=65bit.
/// The part of carry_1 that contributes more than 256 bits is 68 bits, (131+64+128+1)-256=68bit, 1 is carry_0.
/// The part of carry_2 that contributes more than 384 bits is 66 bits, (129+64+256+1)-384=66bit, 1 is carry_1.
#[derive(Clone, Debug)]
pub struct SimpleMul512Gadget<F> {
    // a[0],a[1],a[2],a[3] is the 64-bit limbs of a
    a: [Expression<F>; 4],
    // b[0],b[1],b[2],b[3] is the 64-bit limbs of b
    b: [Expression<F>; 4],
    // c[0],c[1] is the 128-bit limbs of c, represents c_lo and c_hi
    c: [Expression<F>; 2],
    // carry[0], carry[1], carry[2] represents carry_0, carry_1, carry_2
    carry: [Expression<F>; 3],
    // d[0],d[1] is the 128-bit limbs of d, represents d_lo and d_hi
    // d is high 256 bit of the result
    d: [Expression<F>; 2],
    // e[0],e[1] is the 128-bit limbs of e, represents e_lo and e_hi
    // e is low 256 bit of the result
    e: [Expression<F>; 2],
    // input add `prefix` parameter,
    // in order to distinguish the same gadget from calling this function multiple times.
    prefix: String,
}

impl<F: Field> SimpleMul512Gadget<F> {
    /// Returns SimpleLtWordGadget
    pub fn new(
        a: [Expression<F>; 4],
        b: [Expression<F>; 4],
        c: [Expression<F>; 2],
        carry: [Expression<F>; 3],
        d: [Expression<F>; 2],
        e: [Expression<F>; 2],
        prefix: String,
    ) -> Self {
        Self {
            a,
            b,
            c,
            carry,
            d,
            e,
            prefix,
        }
    }
    /// Return SimpleMul512Gadget constraints
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
        let t4 = self.a[1].clone() * self.b[3].clone()
            + self.a[2].clone() * self.b[2].clone()
            + self.a[3].clone() * self.b[1].clone();
        let t5 = self.a[2].clone() * self.b[3].clone() + self.a[3].clone() * self.b[2].clone();
        let t6 = self.a[3].clone() * self.b[3].clone();

        res.push((
            format!(
                "{}, t0 + t1 * 2^64 + c_lo = e_lo + carry_0 * 2^128",
                self.prefix
            ),
            t0.clone() + t1.clone() * pow_of_two::<F>(64) + self.c[0].clone()
                - (self.e[0].clone() + self.carry[0].clone() * pow_of_two::<F>(128)),
        ));
        res.push((
            format!(
                "{}, t2 + t3 * 2^64 + c_hi + carry_0 = e_hi + carry_1 * 2^128",
                self.prefix
            ),
            t2.clone()
                + t3.clone() * pow_of_two::<F>(64)
                + self.c[1].clone()
                + self.carry[0].clone()
                - (self.e[1].clone() + self.carry[1].clone() * pow_of_two::<F>(128)),
        ));
        res.push((
            format!(
                "{}, t4 + t5 * 2^64 + carry_1 = d_lo + carry_2 * 2^128",
                self.prefix
            ),
            t4.clone() + t5.clone() * pow_of_two::<F>(64) + self.carry[1].clone()
                - (self.d[0].clone() + self.carry[2].clone() * pow_of_two::<F>(128)),
        ));
        res.push((
            format!("{}, t6 + carry_2 = d_hi", self.prefix),
            t6.clone() + self.carry[2].clone() - self.d[1].clone(),
        ));
        res
    }
}
