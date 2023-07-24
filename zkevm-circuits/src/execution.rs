pub mod add;
pub mod push;
pub mod stop;

use crate::core_circuit::CoreCircuitConfig;
use crate::witness::Witness;
use crate::{execution::add::AddGadget, witness::CurrentState};

use eth_types::Field;
use halo2_proofs::plonk::{ConstraintSystem, Error};
use trace_parser::Trace;

pub(crate) type ExecutionConfig<F> = CoreCircuitConfig<F>;

pub(crate) trait ExecutionGadget<F: Field> {
    const NAME: &'static str;

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self;

    fn assign_exec_step() -> Result<(), Error> {
        Ok(())
    }

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness;
}

pub(crate) struct ExecutionGadgets<F: Field> {
    add_gadget: AddGadget<F>,
}

impl<F: Field> ExecutionGadgets<F> {
    pub(crate) fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        ExecutionGadgets {
            add_gadget: AddGadget::configure(config, meta),
        }
    }
}
