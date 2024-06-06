use crate::constant::{GAS_LEFT_IDX, MEMORY_CHUNK_PREV_IDX, NUM_AUXILIARY};
use crate::execution::{
    call_4, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 4;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at post_call

/// call_1..call_7为 CALL指令调用之前的操作，即此时仍在父CALL环境，
/// 读取接下来CALL需要的各种操作数，每个call_* gadget负责不同的操作数.
/// call_3负责存储call的父调用环境，不读取任何CALL指令操作数；
/// |gas | addr | value | argsOffset | argsLength | retOffset | retLength
///
///
/// Call3 is the third step of opcode CALL
/// Algorithm overview:
///     1. set call_context's parent_call_id = current call_id
///     2. set call_context's parent_pc = current pc
///     3. set call_context's parent_stack_pointer = current stack_pointer
///     4. set call_context's parent_code_addr = current code_addr
/// Table layout:
///     1. State lookup(call_context write parent_call_id), src: Core circuit, target: State circuit table, 8 columns
///     2. State lookup(call_context write parent_pc), src: Core circuit, target: State circuit table, 8 columns
///     3. State lookup(call_context write parent_stack_pointer), src: Core circuit, target: State circuit table, 8 columns
///     4. State lookup(call_context write parent_code_addr), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX | STATE_STAMP_INIT(1) |
/// +---+-------+-------+-------+----------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call3Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call3Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_3"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_3
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_4::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());
        let pc = meta.query_advice(config.pc, Rotation::cur());
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stack_pointer_prev = meta.query_advice(
            stack_pointer,
            // call_1 and call_2 don't change the stack_pointer value, so stack_pointer
            // of the last gadget equals to the stack_pointer just before the call operation.
            Rotation(-1 * NUM_ROW as i32),
        );
        let memory_chunk_prev_for_next = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            Rotation::cur(),
        );
        let memory_chunk_prev = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );

        let call_id_new = state_stamp_init.clone() + 1.expr();
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        let delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(0.expr()), // 此处的gas_left值与CALL1-3保持一致
            refund: ExpressionOutcome::Delta(0.expr()),
            // 记录父环境的4个状态，所以stamp delta=4
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            // 因为call_3未进行操作数出栈，所以stack pointer delta=0
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        // append auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append call_context constraints
        let mut operands = vec![];
        for i in 0..4 {
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
                        state::CallContextTag::ParentCallId as u8
                    } else if i == 1 {
                        state::CallContextTag::ParentProgramCounter as u8
                    } else if i == 2 {
                        state::CallContextTag::ParentStackPointer as u8
                    } else {
                        state::CallContextTag::ParentCodeContractAddr as u8
                    }
                    .expr(),
                    call_id_new.clone(),
                ),
            );

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // append constraints for state lookup's values
        constraints.extend([
            // 父环境的call_id, pc, stack_pointer低128bit足以标识，
            // 约束高128bit为0
            ("ParentCallId write hi".into(), operands[0][0].clone()),
            (
                "ParentProgramCounter write hi".into(),
                operands[1][0].clone(),
            ),
            ("ParentStackPointer write hi".into(), operands[2][0].clone()),
            // 约束父环境的call_id正确性，此时仍处于父执行环境中，所以等于call_id_cur
            (
                "ParentCallId write lo".into(),
                operands[0][1].clone() - call_id_cur,
            ),
            // 约束父环境的pc正确性，此时仍处于父执行环境中，所以等于pc
            (
                "ParentProgramCounter write lo".into(),
                operands[1][1].clone() - pc,
            ),
            // 约束父环境的stack_pointer正确性，因为未进行出栈操作，所以与上个gadget相等
            (
                "ParentStackPointer write lo".into(),
                operands[2][1].clone() - stack_pointer_prev,
            ),
            // 约束父环境的contract addr正确性，此时仍处于父执行环境中，所以等于code_addr
            (
                "ParentCodeContractAddr write".into(),
                operands[3][0].clone() * pow_of_two::<F>(128) + operands[3][1].clone() - code_addr,
            ),
        ]);
        // append opcode constraint
        constraints.extend([
            ("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr()),
            // append constraint for the next execution state's stamp_init
            (
                "state_init_for_next_gadget correct".into(),
                stamp_init_for_next_gadget - state_stamp_init,
            ),
            (
                "memory_chunk_prev_for_next correct".into(),
                memory_chunk_prev_for_next - memory_chunk_prev,
            ),
        ]);
        // append prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev state is CALL_2, next state is CALL_4
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_2],
                NUM_ROW,
                vec![(ExecutionState::CALL_4, call_4::NUM_ROW, None)],
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
        // 获取core电路父环境的值（callid, pc, stack_pointer, contract_addr），
        // 与state电路lookup
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let call_context_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            ("ParentCallId write".into(), call_context_lookup_0),
            ("ParentProgramCounter write".into(), call_context_lookup_1),
            ("ParentStackPointer write".into(), call_context_lookup_2),
            ("ParentCodeContractAddr write".into(), call_context_lookup_3),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 存储CALL指令父环境的call_id
        let call_context_write_row_0 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentCallId,
            current_state.call_id.into(),
            current_state.call_id_new,
        );
        // 存储CALL指令父环境的pc值
        let call_context_write_row_1 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentProgramCounter,
            trace.pc.into(),
            current_state.call_id_new,
        );
        // 存储CALL指令父环境的stack_pointer值
        let call_context_write_row_2 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentStackPointer,
            current_state.stack_pointer.into(),
            current_state.call_id_new,
        );
        // 存储CALL指令父环境的合约地址
        let call_context_write_row_3 = current_state.get_call_context_write_row(
            state::CallContextTag::ParentCodeContractAddr,
            current_state.code_addr.into(),
            current_state.call_id_new,
        );

        //update current_state's parent_call_id, parent_pc, parent_stack_pointer and parent_code_addr
        // 记录将被执行的CALL对应的父环境状态，便于CALL指令执行完毕后恢复父执行环境
        current_state
            .parent_call_id
            .insert(current_state.call_id_new, current_state.call_id);
        current_state
            .parent_pc
            .insert(current_state.call_id_new, trace.pc);
        current_state
            .parent_stack_pointer
            .insert(current_state.call_id_new, current_state.stack_pointer);
        current_state
            .parent_code_addr
            .insert(current_state.call_id_new, current_state.code_addr);
        //generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        core_row_1.insert_state_lookups([
            &call_context_write_row_0,
            &call_context_write_row_1,
            &call_context_write_row_2,
            &call_context_write_row_3,
        ]);
        let mut core_row_0 = ExecutionState::CALL_3.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // here we use the property that call_id_new == state_stamp + 1, where state_stamp is
        // the stamp just before call operation is executed (instead of before the call_3 gadget).
        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            stamp_init.into()
        );
        // core_row_0写入memory_chunk_prev, 向下传至memory gas计算部分
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            current_state.memory_chunk_prev.into()
        );
        // CALL1到CALL4时还未进行gas计算，此时gas_left为trace.gas
        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                call_context_write_row_0,
                call_context_write_row_1,
                call_context_write_row_2,
                call_context_write_row_3,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call3Gadget {
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
        current_state.call_id = 1;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2;
        current_state.call_id_new = state_stamp_init + 1;

        let trace = prepare_trace_step!(0, OpcodeId::CALL, stack);

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(state_stamp_init.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_4.into_exec_state_core_row(
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
        prover.assert_satisfied();
    }
}
