use crate::execution::{
    ExecutionConfig, ExecutionGadget, ExecutionGadgetAssociated, ExecutionState,
};
use crate::table::LookupEntry;
use crate::witness::{CurrentState, Witness};
use eth_types::Field;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;
use trace_parser::Trace;

pub struct StopGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    fn name(&self) -> &'static str {
        "STOP"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STOP
    }

    fn num_row(&self) -> usize {
        1
    }

    fn get_constraints(
        &self,
        _config: &ExecutionConfig<F>,
        _meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        todo!()
    }

    fn get_lookups(
        &self,
        _config: &ExecutionConfig<F>,
        _meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        todo!()
    }
}

impl<F: Field> ExecutionGadgetAssociated<F> for StopGadget<F> {
    fn new() -> Box<dyn ExecutionGadget<F>> {
        Box::new(Self {
            _marker: PhantomData,
        })
    }

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness {
        let mut core_row0 = ExecutionState::STOP.to_core_row();
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
            ..Default::default()
        }
    }
}
