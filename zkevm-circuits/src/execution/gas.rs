use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::util::ExpressionOutcome;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::{AuxiliaryOutcome, CoreSinglePurposeOutcome};

/// NOTE: this is a temporary implementation
/// +---+-------+-------+-------+--------+
/// |cnt| 8 col | 8 col | 8 col | 8 col  |
/// +---+-------+-------+-------+--------+
/// | 1 | STATE |                        |
/// | 0 | DYNA_SELECTOR   | AUX          |
/// +---+-------+-------+-------+--------+

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
const PC_DELTA: u64 = 1;

pub struct GasGadget<F: Field> {
    _marker: PhantomData<F>,
}

//TODO:fully implement this gadget
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for GasGadget<F>
{
    fn name(&self) -> &'static str {
        "GAS"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::GAS
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            entry.clone(),
            0,
            NUM_ROW,
            1.expr(),
            true,
        ));

        constraints.extend([("opcode".into(), opcode - OpcodeId::GAS.as_u8().expr())]);

        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let gas_remaining = trace.gas - trace.gas_cost;
        let stack_push_0 = current_state.get_push_stack_row(trace, gas_remaining.into());

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_push_0]);
        let core_row_0 = ExecutionState::GAS.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_push_0],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(GasGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use eth_types::U256;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let gas_remaining = U256::from(0xff);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(gas_remaining),
            ..WitnessExecHelper::new()
        };
        let mut trace = prepare_trace_step!(0, OpcodeId::GAS, stack);
        trace.gas = 0x100;
        trace.gas_cost = 0x1;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
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
        prover.assert_satisfied_par();
    }
}
