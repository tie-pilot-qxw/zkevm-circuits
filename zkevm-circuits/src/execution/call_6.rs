use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;

use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    call_7, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 3;

/// CALL_6 用于处理gas相关的call_context操作，在call_6时write trace.gas 和 trace.gas_cost
/// 在POST_CALL_1时read call_context, 从而完成 POST_CALL_1的gas约束
///
/// Call6 is the sixth step of opcode CALL.
/// Table layout:
///     cnt == 0: STAMP_INIT for next gadget
///     cnt == 1:
///         CALLCONTEXT_WRITE_0: write trace.gas
///         CALLCONTEXT_WRITE_1: write trace.gas_cost
/// +-----+---------------------+---------------------+-------------------+
/// | cnt |                     |                     |                   |
/// +-----+---------------------+---------------------+-------------------+
/// | 1   | CALLCONTEXT_WRITE_0 | CALLCONTEXT_WRITE_1 |CALLCONTEXT_WRITE_2|
/// | 0   | DYNA_SELECTOR       | AUX                 | STAMP_INIT (25)   |
/// +-----+---------------------+---------------------+-------------------+
pub struct Call6Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call6Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_6"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_6
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_7::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // 1. call_context_write constraints
        let mut constraints = vec![];
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );

        let call_id = meta.query_advice(config.call_id, Rotation::cur());

        let mut operands = vec![];
        for i in 0..3 {
            // 约束填入core电路的state 状态值
            let entry = config.get_state_lookup(meta, i);
            constraints.append(
                &mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    if i == 0 {
                        state::CallContextTag::ParentGas as u8
                    } else if i == 1 {
                        state::CallContextTag::ParentGasCost as u8
                    } else {
                        state::CallContextTag::ParentMemoryChunk as u8
                    }
                    .expr(),
                    call_id.clone(),
                ),
            );

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            constraints.push(("value_hi == 0".into(), value_hi));
            operands.push(value_lo);
        }

        // 2. auxiliary constraints
        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta.clone()));
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, delta));

        // 3. opcode and state_init constraints
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr()),
            // append constraint for the next execution state's stamp_init
            (
                "state_init_for_next_gadget correct".into(),
                stamp_init_for_next_gadget - state_stamp_init,
            ),
        ]);

        // 4. memory_chunk, trace.gas and trace.gas_cost constraints
        let trace_gas = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            Rotation(-1 * NUM_ROW as i32),
        );
        let trace_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 2],
            Rotation(-1 * NUM_ROW as i32),
        );

        let memory_chunk_aux =
            meta.query_advice(config.get_auxiliary().memory_chunk, Rotation::cur());
        constraints.extend([
            (
                "ParentTraceGas write lo".into(),
                trace_gas - operands[0].clone(),
            ),
            (
                "ParentTraceGasCost write lo".into(),
                trace_gas_cost - operands[1].clone(),
            ),
            (
                "ParentMemoryChunk write lo".into(),
                memory_chunk_aux - operands[2].clone(),
            ),
        ]);

        // 5. prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev state is CALL_5, next state is CALL_7
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_5],
                NUM_ROW,
                vec![(ExecutionState::CALL_7, call_7::NUM_ROW, None)],
                None,
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));

        // 将core 电路中数据在state电路中lookup
        vec![
            ("ParentTraceGas write".into(), call_context_lookup_0),
            ("ParentTraceGasCost write".into(), call_context_lookup_1),
            ("ParentMemoryChunk write".into(), call_context_lookup_2),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 这里callcontext的时候我们传的key是call_id，也即进入call之前的id
        // 这是因为我们在计算post_call_1获取gas值时，此时已经恢复到父环境了，call_id也是父环境的
        // 在call_7时，call_id会被赋值为call_id_new, 在end_call时，会重新赋值为父环境的call_id
        let call_context_write_0 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentGas,
            trace.gas.into(),
            current_state.call_id.into(),
        );

        let call_context_write_1 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentGasCost,
            trace.gas_cost.into(),
            current_state.call_id.into(),
        );

        let call_context_write_2 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentMemoryChunk,
            current_state.memory_chunk.into(),
            current_state.call_id.into(),
        );

        current_state
            .parent_gas
            .insert(current_state.call_id, trace.gas);
        current_state
            .parent_gas_cost
            .insert(current_state.call_id, trace.gas_cost);

        current_state
            .parent_memory_chunk
            .insert(current_state.call_id, current_state.memory_chunk);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([
            &call_context_write_0,
            &call_context_write_1,
            &call_context_write_2,
        ]);

        let mut core_row_0 = ExecutionState::CALL_6.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // 后续计算需要使用的值
        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            stamp_init.into()
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                call_context_write_0,
                call_context_write_1,
                call_context_write_2,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call6Gadget {
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
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[
            0x05.into(),
            0x2222.into(),
            0x04.into(),
            0x1111.into(),
            0x01.into(),
            0x1234.into(),
            0x01.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let state_stamp_init = 3;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_5.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(state_stamp_init.into());
            // 这两个值是prepare_trace_step!中预设的一个值
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1] = Some(100.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 2] = Some(1.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_7.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            //row.pc = 0.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
