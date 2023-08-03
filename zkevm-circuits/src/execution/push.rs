use crate::execution::{
    ExecutionConfig, ExecutionGadget, ExecutionGadgetAssociated, ExecutionState,
};
use crate::table::LookupEntry;
use crate::witness::CurrentState;
use crate::witness::{core, state, Witness};
use eth_types::Field;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;
use trace_parser::Trace;

pub struct PushGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for PushGadget<F> {
    fn name(&self) -> &'static str {
        "PUSH"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::PUSH
    }

    fn num_row(&self) -> usize {
        2
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

impl<F: Field> ExecutionGadgetAssociated<F> for PushGadget<F> {
    fn new() -> Box<dyn ExecutionGadget<F>> {
        Box::new(Self {
            _marker: PhantomData,
        })
    }

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert!(trace.op.is_push());
        let stack = &mut current_state.stack.0;
        let a = trace.push_value.unwrap();
        stack.push(a);
        current_state.stamp_count += 1;
        let core_row1 = core::Row {
            tx_idx: current_state.tx_idx.into(),
            call_id: current_state.call_id.into(),
            code_addr: current_state.code_addr.into(),
            pc: trace.pc.into(),
            opcode: trace.op,
            cnt: 1.into(),
            vers_0: Some((a >> 128).as_u128().into()),
            vers_1: Some(a.low_u128().into()),
            vers_2: Some(current_state.stamp_count.into()),
            vers_3: Some(stack.len().into()),
            vers_4: Some(1.into()),
            ..Default::default()
        };
        let mut core_row0 = ExecutionState::PUSH.to_core_row();
        core_row0.tx_idx = current_state.tx_idx.into();
        core_row0.call_id = current_state.call_id.into();
        core_row0.code_addr = current_state.code_addr.into();
        core_row0.pc = trace.pc.into();
        core_row0.opcode = trace.op;
        core_row0.cnt = 0.into();

        let state_row0 = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some(current_state.stamp_count.into()),
            value_hi: Some((a >> 128).as_u128().into()),
            value_lo: Some(a.low_u128().into()),
            pointer_hi: Some(stack.len().into()),
            ..Default::default()
        };

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row1, core_row0],
            exp: vec![],
            public: vec![],
            state: vec![state_row0],
            arithmetic: vec![],
            ..Default::default()
        }
    }
}
