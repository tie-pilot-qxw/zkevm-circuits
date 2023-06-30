use crate::arithmetic_circuit::operation::{OperationConfig, OperationGadget};
use crate::witness::arithmetic::Tag;
use eth_types::U256;
use gadgets::util::{expr_from_u16s, Expr, TWO_TO_128};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct AddGadget<F>(PhantomData<F>);

impl<F: FieldExt> OperationGadget<F> for AddGadget<F> {
    const NAME: &'static str = "Arithmetic Circuit Add";
    const TAG: Tag = Tag::Add;
    const ROW_NUM: usize = 2;

    fn constraints(
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(&'static str, Expression<F>)> {
        let mut constraints = vec![];
        let a_hi = meta.query_advice(config.operand0_hi, Rotation::cur());
        let a_lo = meta.query_advice(config.operand0_lo, Rotation::cur());
        let b_hi = meta.query_advice(config.operand1_hi, Rotation::cur());
        let b_lo = meta.query_advice(config.operand1_lo, Rotation::cur());
        let c_hi = meta.query_advice(config.operand2_hi, Rotation::cur());
        let c_lo = meta.query_advice(config.operand2_lo, Rotation::cur());
        let carry_hi = meta.query_advice(config.operand3_hi, Rotation::cur());
        let carry_lo = meta.query_advice(config.operand3_lo, Rotation::cur());
        let u16_0_for_c_lo = meta.query_advice(config.u16_0, Rotation::cur());
        let u16_1_for_c_lo = meta.query_advice(config.u16_1, Rotation::cur());
        let u16_2_for_c_lo = meta.query_advice(config.u16_2, Rotation::cur());
        let u16_3_for_c_lo = meta.query_advice(config.u16_3, Rotation::cur());
        let u16_4_for_c_lo = meta.query_advice(config.u16_4, Rotation::cur());
        let u16_5_for_c_lo = meta.query_advice(config.u16_5, Rotation::cur());
        let u16_6_for_c_lo = meta.query_advice(config.u16_6, Rotation::cur());
        let u16_7_for_c_lo = meta.query_advice(config.u16_7, Rotation::cur());
        let u16_sum_for_c_lo = expr_from_u16s(&[
            u16_0_for_c_lo,
            u16_1_for_c_lo,
            u16_2_for_c_lo,
            u16_3_for_c_lo,
            u16_4_for_c_lo,
            u16_5_for_c_lo,
            u16_6_for_c_lo,
            u16_7_for_c_lo,
        ]);
        let u16_0_for_c_hi = meta.query_advice(config.u16_0, Rotation::prev());
        let u16_1_for_c_hi = meta.query_advice(config.u16_1, Rotation::prev());
        let u16_2_for_c_hi = meta.query_advice(config.u16_2, Rotation::prev());
        let u16_3_for_c_hi = meta.query_advice(config.u16_3, Rotation::prev());
        let u16_4_for_c_hi = meta.query_advice(config.u16_4, Rotation::prev());
        let u16_5_for_c_hi = meta.query_advice(config.u16_5, Rotation::prev());
        let u16_6_for_c_hi = meta.query_advice(config.u16_6, Rotation::prev());
        let u16_7_for_c_hi = meta.query_advice(config.u16_7, Rotation::prev());
        let u16_sum_for_c_hi = expr_from_u16s(&[
            u16_0_for_c_hi,
            u16_1_for_c_hi,
            u16_2_for_c_hi,
            u16_3_for_c_hi,
            u16_4_for_c_hi,
            u16_5_for_c_hi,
            u16_6_for_c_hi,
            u16_7_for_c_hi,
        ]);
        constraints.push(("c lo = u16 sum", c_lo.clone() - u16_sum_for_c_lo));
        constraints.push(("c hi = u16 sum", c_hi.clone() - u16_sum_for_c_hi));
        constraints.push((
            "carry hi is bool",
            carry_hi.clone() * (1.expr() - carry_hi.clone()),
        ));
        constraints.push((
            "carry lo is bool",
            carry_lo.clone() * (1.expr() - carry_lo.clone()),
        ));
        constraints.push((
            "c lo + carry lo * 2^128= a lo + b lo",
            c_lo + carry_lo.clone() * TWO_TO_128.expr() - a_lo - b_lo,
        ));
        constraints.push((
            "c hi + carry hi * 2^128= a hi + b hi + carry lo",
            c_hi + carry_hi * TWO_TO_128.expr() - a_hi - b_hi - carry_lo,
        ));
        constraints
    }
}
