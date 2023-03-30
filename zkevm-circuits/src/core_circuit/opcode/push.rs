use crate::add_expression_to_constraints;
use crate::core_circuit::execution::{ExecutionConfig, ExecutionGadget};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub struct Push1Gadget<F> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for Push1Gadget<F> {
    const NAME: &'static str = "PUSH1";

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        meta.create_gate("opcode push1", |meta| {
            let program_counter_next = meta.query_advice(config.program_counter, Rotation::next());
            let stack_stamp_prev = meta.query_advice(config.stack_stamp, Rotation::prev());
            let stack_pointer_prev = meta.query_advice(config.stack_pointer, Rotation::prev());
            let program_counter = meta.query_advice(config.program_counter, Rotation::cur());
            let stack_stamp = meta.query_advice(config.stack_stamp, Rotation::cur());
            let stack_pointer = meta.query_advice(config.stack_pointer, Rotation::cur());
            let is_write_0 = meta.query_advice(config.operand_stack_is_write[0], Rotation::cur());
            let is_write_1 = meta.query_advice(config.operand_stack_is_write[1], Rotation::cur());
            let is_write_2 = meta.query_advice(config.operand_stack_is_write[2], Rotation::cur());
            // let operand_0 = meta.query_advice(config.operand[0], Rotation::cur()); // handled by lookup in core
            let operand_1 = meta.query_advice(config.operand[1], Rotation::cur());
            let operand_2 = meta.query_advice(config.operand[2], Rotation::cur());
            let stack_stamp_0 = meta.query_advice(config.operand_stack_stamp[0], Rotation::cur());
            let stack_stamp_1 = meta.query_advice(config.operand_stack_stamp[1], Rotation::cur());
            let stack_stamp_2 = meta.query_advice(config.operand_stack_stamp[2], Rotation::cur());
            let stack_pointer_0 =
                meta.query_advice(config.operand_stack_pointer[0], Rotation::cur());
            let stack_pointer_1 =
                meta.query_advice(config.operand_stack_pointer[1], Rotation::cur());
            let stack_pointer_2 =
                meta.query_advice(config.operand_stack_pointer[2], Rotation::cur());
            // don't forget about the switch
            let is_push = meta.query_advice(config.is_push, Rotation::cur());
            let q_enable = meta.query_selector(config.q_enable);
            let v = vec![
                (
                    "program counter increment",
                    (program_counter_next - program_counter - 2u8.expr()),
                ),
                (
                    "stack stamp increment",
                    (stack_stamp - stack_stamp_prev.clone() - 1u8.expr()),
                ),
                (
                    "stack pointer increment",
                    (stack_pointer - stack_pointer_prev.clone() - 1u8.expr()),
                ),
                ("stack is write 0 = 1", is_write_0.clone() - 1u8.expr()),
                (
                    "stack stamp 0 = last stamp + 1",
                    stack_stamp_0 - stack_stamp_prev - 1u8.expr(),
                ),
                (
                    "stack pointer 0 = last pointer + is_write",
                    stack_pointer_0 - stack_pointer_prev - is_write_0,
                ),
                ("other stack is write = 0", is_write_1),
                ("other stack is write = 0", is_write_2),
                ("other operand = 0", operand_1),
                ("other operand = 0", operand_2),
                ("other stack stamp = 0", stack_stamp_1),
                ("other stack stamp = 0", stack_stamp_2),
                ("other stack pointer = 0", stack_pointer_1),
                ("other stack pointer = 0", stack_pointer_2),
            ];
            add_expression_to_constraints!(v, q_enable.clone() * is_push.clone())
        });
        Push1Gadget {
            _marker: PhantomData,
        }
    }
}
