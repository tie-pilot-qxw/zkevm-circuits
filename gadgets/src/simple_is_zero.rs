//! SimpleIsZero gadget helps to generate the expression 1-value*value_inv and the corresponding constraint.

use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// SimpleIsZero helps to generate the expression 1-value*value_inv and the corresponding constraint.
#[derive(Clone, Debug)]
pub struct SimpleIsZero<F> {
    value: Expression<F>,
    value_inv: Expression<F>,
    prefix: String,
}

impl<F: Field> SimpleIsZero<F> {
    /// given value, value_inv and the prefix("hi" or "lo"), return a new SimpleIsZero instance
    pub fn new(value: &Expression<F>, value_inv: &Expression<F>, prefix: String) -> Self {
        Self {
            value: value.clone(),
            value_inv: value_inv.clone(),
            prefix: prefix,
        }
    }

    /// return the constraint to ensure value * value_inv == 1 or value == 0
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let mut res: Vec<(String, Expression<F>)> = Vec::new();

        let expr = self.expr();

        res.push((
            String::from(format!("{}_inv", self.prefix)),
            self.value.clone() * expr.clone(),
        ));

        res
    }

    /// return the expression 1 - value * value_inv
    ///
    /// if value=0 return 1
    /// else return 0
    pub fn expr(&self) -> Expression<F> {
        1.expr() - self.value.clone() * self.value_inv.clone()
    }
}
