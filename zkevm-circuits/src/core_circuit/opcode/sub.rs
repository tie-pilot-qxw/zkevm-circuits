use crate::add_expression_to_constraints;
use crate::core_circuit::execution::{ExecutionConfig, ExecutionGadget};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::str::FromStr;

pub struct SubGadget<F> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for SubGadget<F> {
    const NAME: &'static str = "SUB";

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        meta.create_gate(Self::NAME, |meta| {
            let program_counter_next = meta.query_advice(config.program_counter, Rotation::next());
            let stack_stamp_prev = meta.query_advice(config.stack_stamp, Rotation::prev());
            let stack_pointer_prev = meta.query_advice(config.stack_pointer, Rotation::prev());
            let program_counter = meta.query_advice(config.program_counter, Rotation::cur());
            let stack_stamp = meta.query_advice(config.stack_stamp, Rotation::cur());
            let stack_pointer = meta.query_advice(config.stack_pointer, Rotation::cur());
            let is_write_0 = meta.query_advice(config.operand_stack_is_write[0], Rotation::cur());
            let is_write_1 = meta.query_advice(config.operand_stack_is_write[1], Rotation::cur());
            let is_write_2 = meta.query_advice(config.operand_stack_is_write[2], Rotation::cur());
            let operand_0 = meta.query_advice(config.operand[0], Rotation::cur());
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
            let opcode_id = OpcodeId::from_str(Self::NAME)
                .expect(&format!("gadget name {} is wrong", Self::NAME));
            let is_opcode = config
                .execution_state_selector
                .selector(meta, opcode_id.as_u8() as usize);
            let q_enable = meta.query_selector(config.q_enable);
            let v = vec![
                ("a-b=c", (operand_0.clone() - operand_1.clone() - operand_2)),
                (
                    "program counter increment",
                    (program_counter_next - program_counter - 1u8.expr()),
                ),
                (
                    "stack stamp increment",
                    (stack_stamp - stack_stamp_prev.clone() - 3u8.expr()),
                ),
                (
                    "stack pointer increment",
                    (stack_pointer - stack_pointer_prev.clone() + 1u8.expr()),
                ),
                ("stack is write 0 = 0", is_write_0.clone()),
                ("stack is write 1 = 0", is_write_1.clone()),
                ("stack is write 2 = 1", is_write_2 - 1u8.expr()),
                (
                    "stack stamp 0 = last stamp + 1",
                    stack_stamp_0.clone() - stack_stamp_prev - 1u8.expr(),
                ),
                (
                    "stack stamp 0 + 1 = stack stamp 1",
                    stack_stamp_1.clone() - stack_stamp_0.clone() - 1u8.expr(),
                ),
                (
                    "stack stamp 1 + 1 = stack stamp 2",
                    stack_stamp_2 - stack_stamp_1 - 1u8.expr(),
                ),
                (
                    "stack pointer 0 = last pointer + is_write",
                    stack_pointer_0.clone() - stack_pointer_prev - is_write_0,
                ),
                (
                    "stack pointer 0 - 1 = stack pointer 1",
                    stack_pointer_1.clone() - stack_pointer_0.clone() + 1u8.expr(),
                ),
                (
                    "stack pointer 1 = stack pointer 2",
                    stack_pointer_2 - stack_pointer_1,
                ),
            ];
            // multiply enable and is_opcode to all constraints
            add_expression_to_constraints!(v, q_enable.clone() * is_opcode.clone())
        });
        SubGadget {
            _marker: PhantomData,
        }
    }
}
