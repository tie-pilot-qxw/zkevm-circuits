// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Simple binary number used to split the value into binary

use std::ops::IndexMut;

use crate::binary_number::AsBits;
use crate::util::{and, not, Expr};
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Simple binary number used to store value in binary (0/1) form and get the expression of value
#[derive(Clone, Debug)]
pub struct SimpleBinaryNumber<F, const N: usize> {
    bits: [Expression<F>; N],
}

impl<F: Field, const N: usize> SimpleBinaryNumber<F, N> {
    /// Create a simple binary number with input of array of expressions
    pub fn new(bits: &[Expression<F>; N]) -> Self {
        Self { bits: bits.clone() }
    }

    /// Get the constraints
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let res: Vec<(String, Expression<F>)> = self
            .bits
            .iter()
            .enumerate()
            .map(|(i, x)| {
                (
                    String::from(format!("bit {} is 0/1", i)),
                    x.clone() * (x.clone() - 1.expr()),
                )
            })
            .collect();
        res
    }

    /// Returns the expression value of the bits
    pub fn value(&self) -> Expression<F> {
        self.bits
            .iter()
            .fold(0.expr(), |result, bit| bit.clone() + result * 2.expr())
    }

    /// Returns a binary expression that evaluates to 1 if expressions are equal
    /// to value as bits. The returned expression is of degree N.
    pub fn value_equals_expr<S: AsBits<N>>(&self, value: S) -> Expression<F> {
        and::expr(
            value
                .as_bits()
                .iter()
                .zip(&self.bits)
                .map(|(&bit, expression)| {
                    if bit {
                        expression.clone()
                    } else {
                        not::expr(expression.clone())
                    }
                }),
        )
    }
}

/// split the value into binary and assign the value
pub fn simple_binary_number_assign<A, T: IndexMut<usize, Output = A>, const N: usize>(
    target: &mut T,
    positions: [usize; N],
    value: usize,
    assign_or_panic: impl Fn(&mut A, u8),
) {
    let bits: [bool; N] = value.as_bits();
    for (index, pos) in positions.into_iter().enumerate() {
        let value: u8 = if bits[index] { 1 } else { 0 };
        assign_or_panic(&mut target[pos], value);
    }
}
