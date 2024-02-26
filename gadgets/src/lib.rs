//! # ZKEVM-Gadgets
//!
//! A collection of reusable gadgets for the zk_evm circuits.

#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

pub mod batched_is_zero;
pub mod binary_number;
pub mod binary_number_with_real_selector;
pub mod dynamic_selector;
pub mod is_zero;
pub mod is_zero_with_rotation;
pub mod less_than;
pub mod mul_add;
pub mod simple_binary_number;
pub mod simple_is_zero;
pub mod simple_lt;
pub mod simple_lt_word;
pub mod simple_mul;
pub mod simple_mul_512;
pub mod simple_seletor;
pub mod util;

use eth_types::Field;
use halo2_proofs::plonk::Expression;

/// Restrict an expression to be a boolean.
pub fn bool_check<F: Field>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

/// Restrict an expression such that 0 <= word < range.
pub fn range_check<F: Field>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(F::from(i as u64)) - word.clone())
    })
}
