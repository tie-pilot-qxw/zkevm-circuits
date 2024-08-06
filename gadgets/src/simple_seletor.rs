// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Simple selector used to select one target among N items.

use eth_types::Field;
use halo2_proofs::plonk::Expression;
use std::{marker::PhantomData, ops::IndexMut};

use crate::util::Expr;

/// Simple selector used to select one target among N items.
/// It uses N binary (0/1) selector expressions
pub struct SimpleSelector<F, const N: usize> {
    targets: [Expression<F>; N],
    _marker: PhantomData<F>,
}

impl<F: Field, const N: usize> SimpleSelector<F, N> {
    /// Create a simple selector with input of array of expressions
    pub fn new(targets: &[Expression<F>; N]) -> Self {
        Self {
            targets: targets.clone(),
            _marker: Default::default(),
        }
    }

    /// Get the constraints
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let mut res: Vec<(String, Expression<F>)> = self
            .targets
            .iter()
            .enumerate()
            .map(|(i, x)| {
                (
                    String::from(format!("selector {} is 0/1", i)),
                    x.clone() * (x.clone() - 1.expr()),
                )
            })
            .collect();
        res.push((
            String::from("selector sum is 1"),
            self.targets.iter().fold(1.expr(), |acc, x| acc - x.clone()),
        ));
        res
    }

    /// Select the target from items, using sum of items with 0/1 selector value
    pub fn select(&self, items: &[Expression<F>; N]) -> Expression<F> {
        (0..N).into_iter().fold(0.expr(), |acc, x| {
            acc + self.targets[x].clone() * items[x].clone()
        })
    }
}

///  This function assign the target value 1 at index and value 0 at others among N values
pub fn simple_selector_assign<A, T: IndexMut<usize, Output = A>, const N: usize>(
    target: &mut T,
    positions: [usize; N],
    index: usize,
    assign_or_panic: impl Fn(&mut A, u8),
) {
    assert!(index < N, "assign input index {} out of range {}", index, N);
    for (loc, pos) in positions.into_iter().enumerate() {
        let value: u8 = if loc == index { 1 } else { 0 };
        assign_or_panic(&mut target[pos], value);
    }
}
