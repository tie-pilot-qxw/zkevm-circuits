//! Todo: Docs

use eth_types::Field;
use halo2_proofs::plonk::{Advice, Column, Expression};
use std::marker::PhantomData;

use crate::util::Expr;

/// Todo: Docs
pub struct SimpleSelector<F, const N: usize> {
    targets: [Expression<F>; N],
    _marker: PhantomData<F>,
}

impl<F: Field, const N: usize> SimpleSelector<F, N> {
    /// Todo Docs
    pub fn new_selector(targets: &[Expression<F>; N]) -> Self {
        Self {
            targets: targets.clone(),
            _marker: Default::default(),
        }
    }

    /// Todo Docs
    pub fn gen_constraints(&self) -> Vec<(String, Expression<F>)> {
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

    /// Todo Docs
    pub fn select(&self, items: &[Expression<F>; N]) -> Expression<F> {
        (0..N).into_iter().fold(0.expr(), |acc, x| {
            acc + self.targets[x].clone() * items[x].clone()
        })
    }
}
