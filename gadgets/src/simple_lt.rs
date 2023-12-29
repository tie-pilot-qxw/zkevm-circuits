//! SimpleLtGadget gadget
use crate::util::pow_of_two;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER` to prevent overflow:
/// values are stored in a single field element and two of these are added
/// together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**N_BYTES` and `lt` is boolean, `lt` can only
/// be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct SimpleLtGadget<F, const N_BYTES: usize> {
    lhs: Expression<F>,
    rhs: Expression<F>,
    lt: Expression<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: Expression<F>, /* The byte values of `diff`.
                        * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                        * `lhs - rhs + range` otherwise.
                        * the external need to constrain diff within the range scope*/
    range: F, // The range of the inputs, `256**N_BYTES`
}

impl<F: Field, const N_BYTES: usize> SimpleLtGadget<F, N_BYTES> {
    /// Returns SimpleLtGadget
    pub fn new(
        lhs: &Expression<F>,
        rhs: &Expression<F>,
        lt: &Expression<F>,
        diff: &Expression<F>,
    ) -> Self {
        let range = pow_of_two(N_BYTES * 8);
        Self {
            lhs: lhs.clone(),
            rhs: rhs.clone(),
            lt: lt.clone(),
            diff: diff.clone(),
            range,
        }
    }

    /// Returns constraints
    pub fn get_constraints(&self) -> Vec<(String, Expression<F>)> {
        let mut res: Vec<(String, Expression<F>)> = Vec::new();

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        res.push((
            "lhs - rhs == diff - (lt ⋅ range)".to_string(),
            (self.lhs.clone() - self.rhs.clone())
                - (self.diff.clone() - self.lt.clone() * self.range.clone()),
        ));

        res
    }

    /// Returns SimpleLtGadget lt expression
    pub fn expr(&self) -> Expression<F> {
        self.lt.clone()
    }
}
