use crate::execution::{Auxiliary, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 1;

pub struct StopGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for StopGadget<F>
{
    fn name(&self) -> &'static str {
        "STOP"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STOP
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, super::end_block::NUM_ROW) // end unusable rows is super::end_block::NUM_ROW
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let Auxiliary {
            state_stamp,
            stack_pointer,
            log_stamp,
            gas_left,
            refund,
            memory_chunk,
            read_only,
            ..
        } = config.get_auxiliary();
        let state_stamp_cur = meta.query_advice(state_stamp, Rotation::cur());
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let stack_pointer_cur = meta.query_advice(stack_pointer, Rotation::cur());
        let stack_pointer_prev = meta.query_advice(stack_pointer, Rotation(-1 * NUM_ROW as i32));
        let log_stamp_cur = meta.query_advice(log_stamp, Rotation::cur());
        let log_stamp_prev = meta.query_advice(log_stamp, Rotation(-1 * NUM_ROW as i32));
        let read_only_cur = meta.query_advice(read_only, Rotation::cur());
        let read_only_prev = meta.query_advice(read_only, Rotation(-1 * NUM_ROW as i32));
        // next execution state should be END_BLOCK, temporarily todo
        let next_is_end_block = config.execution_state_selector.selector(
            meta,
            ExecutionState::END_BLOCK as usize,
            Rotation(super::end_block::NUM_ROW as i32),
        );
        let next_end_block_cnt_is_zero = config
            .cnt_is_zero
            .expr_at(meta, Rotation(super::end_block::NUM_ROW as i32));

        vec![
            ("opcode".into(), opcode - OpcodeId::STOP.as_u8().expr()),
            ("next pc".into(), pc_next - pc_cur), // if stop, next pc is same
            ("state stamp".into(), state_stamp_cur - state_stamp_prev),
            (
                "stack pointer".into(),
                stack_pointer_cur - stack_pointer_prev,
            ),
            ("log stamp".into(), log_stamp_cur - log_stamp_prev),
            ("read only".into(), read_only_cur - read_only_prev),
            (
                "next is END_BLOCK".into(),
                next_end_block_cnt_is_zero * next_is_end_block - 1.expr(),
            ),
        ]
    }

    fn get_lookups(
        &self,
        _: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        _: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }

    fn gen_witness(&self, trace: &Trace, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::STOP);
        let core_row = ExecutionState::STOP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(StopGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let mut current_state = WitnessExecHelper::new();
        // prepare a trace
        let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
        let padding_begin_row = |current_state| {
            ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let padding_end_row = |current_state| {
            ExecutionState::END_BLOCK.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
