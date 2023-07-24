use crate::execution::{ExecutionConfig, ExecutionGadget};
use crate::witness::{arithmetic, CurrentState};
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

pub struct AddGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for AddGadget<F> {
    const NAME: &'static str = "ADD";

    fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        AddGadget {
            _marker: PhantomData,
        }
    }

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert_eq!(trace.op, OpcodeId::ADD);
        let stack = &mut current_state.stack.0;
        assert!(stack.len() >= 2);
        assert!(stack.len() < 1024);
        let a = stack.pop().unwrap();
        let b = stack.pop().unwrap();
        let (c, carry_hi) = a.overflowing_add(b);
        stack.push(c);
        current_state.stamp_count += 3;

        let core_row2 = core::Row {
            tx_idx: current_state.tx_idx.into(),
            call_id: current_state.call_id.into(),
            code_addr: current_state.code_addr.into(),
            pc: trace.pc.into(),
            opcode: trace.op,
            cnt: 2.into(),
            vers_0: Some((a >> 128).as_u128().into()),
            vers_1: Some(a.low_u128().into()),
            vers_2: Some((b >> 128).as_u128().into()),
            vers_3: Some(b.low_u128().into()),
            vers_4: Some((c >> 128).as_u128().into()),
            vers_5: Some(c.low_u128().into()),
            ..Default::default()
        };
        let core_row1 = core::Row {
            tx_idx: current_state.tx_idx.into(),
            call_id: current_state.call_id.into(),
            code_addr: current_state.code_addr.into(),
            pc: trace.pc.into(),
            opcode: trace.op,
            cnt: 1.into(),
            vers_0: Some((a >> 128).as_u128().into()),
            vers_1: Some(a.low_u128().into()),
            vers_2: Some((current_state.stamp_count - 2).into()),
            vers_3: Some((stack.len() + 1).into()),
            vers_4: Some(0.into()),
            vers_5: Some((b >> 128).as_u128().into()),
            vers_6: Some(b.low_u128().into()),
            vers_7: Some((current_state.stamp_count - 1).into()),
            vers_8: Some(stack.len().into()),
            vers_9: Some(0.into()),
            vers_10: Some((c >> 128).as_u128().into()),
            vers_11: Some(c.low_u128().into()),
            vers_12: Some(current_state.stamp_count.into()),
            vers_13: Some(stack.len().into()),
            vers_14: Some(1.into()),
            ..Default::default()
        };
        let mut core_row0 = core::ExecutionState::ADD.to_core_row();
        core_row0.tx_idx = current_state.tx_idx.into();
        core_row0.call_id = current_state.call_id.into();
        core_row0.code_addr = current_state.code_addr.into();
        core_row0.pc = trace.pc.into();
        core_row0.opcode = trace.op;
        core_row0.cnt = 0.into();

        let state_row2 = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((current_state.stamp_count - 2).into()),
            value_hi: Some((a >> 128).as_u128().into()),
            value_lo: Some(a.low_u128().into()),
            pointer_hi: Some((stack.len() + 1).into()),
            ..Default::default()
        };
        let state_row1 = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((current_state.stamp_count - 1).into()),
            value_hi: Some((b >> 128).as_u128().into()),
            value_lo: Some(b.low_u128().into()),
            pointer_hi: Some(stack.len().into()),
            ..Default::default()
        };
        let state_row0 = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some(current_state.stamp_count.into()),
            value_hi: Some((c >> 128).as_u128().into()),
            value_lo: Some(c.low_u128().into()),
            pointer_hi: Some(stack.len().into()),
            ..Default::default()
        };

        let arithmetic_row = arithmetic::Row {
            operand0_hi: Some((a >> 128).into()),
            operand0_lo: Some(a.low_u128().into()),
            operand1_hi: Some((b >> 128).into()),
            operand1_lo: Some(b.low_u128().into()),
            operand2_hi: Some((c >> 128).into()),
            operand2_lo: Some(c.low_u128().into()),
            operand3_hi: Some((carry_hi as u8).into()),
            ..Default::default()
        };

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row2, core_row1, core_row0],
            exp: vec![],
            public: vec![],
            state: vec![state_row2, state_row1, state_row0],
            arithmetic: vec![arithmetic_row],
        }
    }
}
