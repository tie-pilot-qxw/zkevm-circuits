// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
pub struct UnsupportedGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for UnsupportedGadget<F>
{
    fn name(&self) -> &'static str {
        "UNSUPPORTED"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::UNSUPPORTED
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        _config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        vec![]
    }
    fn get_lookups(
        &self,
        _config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }
    // Func gen_witness(...) is supposed to emtpy.
    // But trivially set it to be emtpy will fail for
    // it will not pass the mockProver.
    // So we set it to be the same with the one in keccak.rs.
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, _) = current_state.get_pop_stack_row_value(&trace);

        let (stack_pop_1, _) = current_state.get_pop_stack_row_value(&trace);

        let stack_push_0 =
            current_state.get_push_stack_row(trace, current_state.stack_top.unwrap_or_default());

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        let core_row_0 = ExecutionState::UNSUPPORTED.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(UnsupportedGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    use env_logger;
    fn run(opcode: OpcodeId) {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, opcode, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
    #[test]
    fn test_unsupported_create() {
        run(OpcodeId::CREATE)
    }
    #[test]
    fn test_unsupported_create2() {
        run(OpcodeId::CREATE2)
    }
    #[test]
    fn test_unsupported_callcode() {
        run(OpcodeId::CALLCODE)
    }
    #[test]
    fn test_unsupported_selfdestruct() {
        run(OpcodeId::SELFDESTRUCT)
    }
    #[test]
    fn test_unsupported_opcode() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Warn)
            .try_init();
        let _ = ExecutionState::from_opcode(OpcodeId::CREATE);
        let _ = ExecutionState::from_opcode(OpcodeId::CREATE2);
        let _ = ExecutionState::from_opcode(OpcodeId::CALLCODE);
        let _ = ExecutionState::from_opcode(OpcodeId::SELFDESTRUCT);
    }
}
