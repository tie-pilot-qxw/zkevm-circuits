// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! SimpleLtWordGadget gadget
use crate::simple_lt::SimpleLtGadget;
use crate::util::pow_of_two;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Lt_Word_N_BYTES is the number of bytes in a word.
pub const LT_WORD_N_BYTES: usize = 16;

/// Returns (lt_hi):
/// - `lt_hi` is `1` when `lhs_hi < rhs_hi`, `0` otherwise.
/// lhs_hi and rhs_hi is the high `LT_WORD_N_BYTES * 8` bits of the operand
/// supports comparison between 256 bit operands
#[derive(Clone, Debug)]
pub struct SimpleLtWordGadget<F, const LT_WORD_N_BYTES: usize> {
    lhs_hi: Expression<F>,
    rhs_hi: Expression<F>,
    lt_hi: Expression<F>, // `1` when `lhs_hi < rhs_hi`, `0` otherwise.
    diff_hi: Expression<F>, /* The byte values of `diff`.
                           * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                           * `lhs - rhs + range` otherwise.
                           * the external need to constrain diff within the range scope*/
    range: F, // The range of the inputs, `256**N_BYTES`

    lt_lo: SimpleLtGadget<F, LT_WORD_N_BYTES>,
}

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
impl<F: Field> SimpleLtWordGadget<F, LT_WORD_N_BYTES> {
    /// Returns SimpleLtWordGadget
    pub fn new(
        lhs: &Expression<F>,
        rhs: &Expression<F>,
        lt: &Expression<F>,
        diff: &Expression<F>,
        lt_lo: SimpleLtGadget<F, LT_WORD_N_BYTES>,
    ) -> Self {
        let range = pow_of_two(LT_WORD_N_BYTES * 8);
        Self {
            lhs_hi: lhs.clone(),
            rhs_hi: rhs.clone(),
            lt_hi: lt.clone(),
            diff_hi: diff.clone(),
            lt_lo,
            range,
        }
    }
    /// Return constraints
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let mut res: Vec<(String, Expression<F>)> = Vec::new();

        res.extend(self.lt_lo.get_constraints());
        res.extend(vec![(
            "lhs_hi - rhs_hi - lt_lo == diff_hi - lt_hi * range".to_string(),
            (self.lhs_hi.clone() - self.rhs_hi.clone() - self.lt_lo.expr())
                - (self.diff_hi.clone() - self.lt_hi.clone() * self.range.clone()),
        )]);

        res
    }

    /// Return SimpleLtWordGadget lt_hi expression
    pub fn expr(&self) -> Expression<F> {
        self.lt_hi.clone()
    }
}
