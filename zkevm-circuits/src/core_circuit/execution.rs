use std::ops::Add;

use crate::core_circuit::opcode::add::AddGadget;
use crate::core_circuit::opcode::sub::SubGadget;
use crate::core_circuit::opcode::mul::MulGadget;
use crate::core_circuit::opcode::push::Push1Gadget;
use crate::core_circuit::opcode::stop::StopGadget;
use crate::core_circuit::CoreCircuitConfig;

use eth_types::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{ConstraintSystem, Error};


pub(crate) type ExecutionConfig<F> = CoreCircuitConfig<F>;

pub(crate) trait ExecutionGadget<F: FieldExt> {
    const NAME: &'static str;

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self;

    fn assign_exec_step() -> Result<(), Error> {
        Ok(())
    }
}

pub(crate) struct ExecutionGadgets<F> {
    stop_gadget: StopGadget<F>,
    add_gadget: AddGadget<F>,
    mul_gadget: MulGadget<F>,
    sub_gadget:SubGadget<F>,
    push1_gadget: Push1Gadget<F>,
}

impl<F: Field> ExecutionGadgets<F> {
    pub(crate) fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        ExecutionGadgets {
            stop_gadget: StopGadget::configure(config, meta),
            add_gadget: AddGadget::configure(config, meta),
            mul_gadget: MulGadget::configure(config, meta),
            sub_gadget: SubGadget::configure(config, meta),
            push1_gadget: Push1Gadget::configure(config, meta),
        }
    }
}
