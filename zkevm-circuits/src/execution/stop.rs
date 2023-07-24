use crate::execution::{ExecutionConfig, ExecutionGadget};
use crate::witness::CurrentState;
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

pub struct StopGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        StopGadget {
            _marker: PhantomData,
        }
    }

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness {
        let mut core_row0 = core::ExecutionState::STOP.to_core_row();
        core_row0.tx_idx = current_state.tx_idx.into();
        core_row0.call_id = current_state.call_id.into();
        core_row0.code_addr = current_state.code_addr.into();
        core_row0.pc = trace.pc.into();
        core_row0.opcode = trace.op;
        core_row0.cnt = 0.into();

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row0],
            exp: vec![],
            public: vec![],
            state: vec![],
            arithmetic: vec![],
        }
    }
}
