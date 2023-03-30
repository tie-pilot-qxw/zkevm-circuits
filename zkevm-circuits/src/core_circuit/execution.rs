use crate::core_circuit::opcode::push::Push1Gadget;
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
    push1_gadget: Push1Gadget<F>,
}

impl<F: Field> ExecutionGadgets<F> {
    pub(crate) fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        ExecutionGadgets {
            push1_gadget: Push1Gadget::configure(config, meta),
        }
    }
}
