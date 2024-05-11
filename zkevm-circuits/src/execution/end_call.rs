use crate::constant::{END_CALL_NEXT_IS_END_TX, END_CALL_NEXT_IS_POST_CALL, NUM_AUXILIARY};
use crate::execution::{
    end_tx, post_call, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 4;
/// The index of column to store parent_call_id_inv in row_0
/// (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const PARENT_CALL_ID_INV_COL_IDX: usize = 1;
/// The index of column to store returndatasize in row_0
/// (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const RETURNDATA_SIZE_COL_IDX: usize = 2;

/// 当evm 操作码为 STOP、REVERT、RETURN时，先执行对应的指令的gadget，
/// 再执行END_CALL gadget，进行父状态的恢复
/// EndCall recovers the current state from the callee to the caller.
/// More precisely, it reads parent_call_id, parent_pc, parent_stack_pointer and parent_code_addr
/// from call_context, and constraint the next state's call_id, pc and code_addr
/// as well as it's own stack_pointer value in Auxiliary cells.
///
/// Table layout:
///     1. State lookup(call_context read parent_call_id), src: Core circuit, target: State circuit table, 8 columns
///     2. State lookup(call_context read parent_pc), src: Core circuit, target: State circuit table, 8 columns
///     3. State lookup(call_context read parent_stack_pointer), src: Core circuit, target: State circuit table, 8 columns
///     4. State lookup(call_context read parent_code_addr), src: Core circuit, target: State circuit table, 8 columns
///     5. SUCCESS, indicating whether the execution succeed and used by the next state (only when the next state is POST_CALL), 1 column
///     6. PARENT_CALL_ID_INV, the inverse of parent_call_id used to determine whether parent_call_id ==0, 1 column
///     7. RETURNDATA_SIZE, the record of returndata_size used by the next state (only when the next state is POST_CALL)
///
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX    |SUCCESS(1)| PARENT_CALL_ID_INV(1)| RETURNDATA_SIZE(1)|
/// +---+-------+-------+-------+----------+
pub struct EndCallGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndCallGadget<F>
{
    fn name(&self) -> &'static str {
        "END_CALL"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_CALL
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, post_call::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());

        let Auxiliary { stack_pointer, .. } = config.get_auxiliary();
        let stack_pointer_prev = meta.query_advice(stack_pointer, Rotation(-1 * NUM_ROW as i32));

        let returndata_size = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let returndata_size_for_next_gadget = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + RETURNDATA_SIZE_COL_IDX],
            Rotation::cur(),
        );

        let mut constraints: Vec<(String, Expression<F>)> = vec![];
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            // 约束写入的4个父状态
            constraints.append(
                &mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    // 4个状态都非写入操作，因此为false
                    false,
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
                    call_id_cur.expr(),
                ),
            );
            // 记录每个state row的值
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }
        // 从state row的操作数中提取4个父状态
        let parent_call_id = operands[0][1].clone();
        let parent_pc = operands[1][1].clone();
        let parent_stack_pointer = operands[2][1].clone();
        let parent_code_addr =
            operands[3][0].clone() * pow_of_two::<F>(128) + operands[3][1].clone();
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            // stack_pointer will recover to parent_stack_pointer if parent_call_id != 0
            stack_pointer: ExpressionOutcome::Delta(
                parent_call_id.clone() * (parent_stack_pointer - stack_pointer_prev),
            ),
            ..Default::default()
        };

        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        //constraint success is either 0 or 1
        let success = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        constraints.extend([(
            "success is 0 or 1".into(),
            success.clone() * (success - 1.expr()),
        )]);
        //constraint the recorded returndata_size
        constraints.extend([(
            "returndata_size_for_next_gadget is correct".into(),
            returndata_size_for_next_gadget - returndata_size,
        )]);
        // append prev and current core constraints
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // 非root call时约束call_id，pc，code_addr 为父状态，因为CALL调用结束后恢复
        // 这些状态至父状态； tx_id不变，因为此时还处于一个执行过程中；
        // 如：当call 为root call时，下一个状态为END_TX，否则为POST_CALL
        let core_single_delta = CoreSinglePurposeOutcome {
            call_id: ExpressionOutcome::To(parent_call_id.clone()),
            pc: ExpressionOutcome::To(parent_pc),
            code_addr: ExpressionOutcome::To(parent_code_addr),
            ..Default::default()
        };
        // append core single purpose constraints
        let core_single_purpose_constraints_raw =
            config.get_next_single_purpose_constraints(meta, core_single_delta);
        // enable the single purpose constraints when parent_call_id != 0
        constraints.append(
            &mut core_single_purpose_constraints_raw
                .into_iter()
                .map(|constraint| (constraint.0, parent_call_id.clone() * constraint.1))
                .collect(),
        );

        let parent_call_id_inv = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + PARENT_CALL_ID_INV_COL_IDX],
            Rotation::cur(),
        );
        let parent_call_id_is_zero = SimpleIsZero::new(
            &parent_call_id,
            &parent_call_id_inv,
            String::from("parent_call_id"),
        );
        constraints.extend(parent_call_id_is_zero.get_constraints());
        let next_is_end_tx = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + END_CALL_NEXT_IS_END_TX],
            Rotation::cur(),
        );
        let next_is_post_call = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + END_CALL_NEXT_IS_POST_CALL],
            Rotation::cur(),
        );
        // prev state is RETURN_REVERT or STOP
        // next state is END_TX or POST_CALL
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::RETURN_REVERT, ExecutionState::STOP],
                NUM_ROW,
                vec![
                    // 当为root call时，约束接下来的状态为END_TX(交易执行结束)
                    (
                        ExecutionState::END_TX,
                        end_tx::NUM_ROW,
                        Some(next_is_end_tx),
                    ),
                    // 当为一笔交易的中间合约调用，非root call时，约束下一个状态为POST_CALL
                    // POST_CALL处理CALL调用的执行结果以及对应的栈上操作数清理
                    (
                        ExecutionState::POST_CALL,
                        post_call::NUM_ROW,
                        Some(next_is_post_call),
                    ),
                ],
                Some(vec![
                    parent_call_id_is_zero.expr(),
                    1.expr() - parent_call_id_is_zero.expr(),
                ]),
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // lookup 当前对应的4个父调用的状态是否一致
        // src: core circuit;  dst: state circuit
        let call_context_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let call_context_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let call_context_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let call_context_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            (
                "callcontext read parent_call_id".into(),
                call_context_lookup_0,
            ),
            (
                "callcontext read parent_program_counter".into(),
                call_context_lookup_1,
            ),
            (
                "callcontext read parent_stack_pointer".into(),
                call_context_lookup_2,
            ),
            (
                "callcontext read parent_code_addr".into(),
                call_context_lookup_3,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 生成当前CALL对应的parent状态，便于CALL调用结束后恢复
        // （parent_callid, parent_pc, parent_stack_pointer, parent_contract_addr）
        let call_context_read_row_0 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentCallId,
            current_state.parent_call_id[&current_state.call_id].into(),
            current_state.call_id,
        );
        let call_context_read_row_1 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentProgramCounter,
            current_state.parent_pc[&current_state.call_id].into(),
            current_state.call_id,
        );
        let call_context_read_row_2 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentStackPointer,
            current_state.parent_stack_pointer[&current_state.call_id].into(),
            current_state.call_id,
        );
        let call_context_read_row_3 = current_state.get_call_context_read_row_with_arbitrary_tag(
            state::CallContextTag::ParentCodeContractAddr,
            current_state.parent_code_addr[&current_state.call_id].into(),
            current_state.call_id,
        );

        // 当前CALL非 root call时(即交易中的第一次合约调用)，call调用结束后，
        // 恢复stack_pointer至它的父状态; root call时整个交易结束，因此不用恢复
        if current_state.parent_call_id[&current_state.call_id] != 0 {
            current_state.stack_pointer =
                current_state.parent_stack_pointer[&current_state.call_id];
        }
        // 注意，core_row_1/2 此时辅助列的 stack_pointer为父调用的栈帧
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // insert lookup: Core ---> State
        // 将上面生成的当前Call对应的4个父状态写入core_row_1
        core_row_1.insert_state_lookups([
            &call_context_read_row_0,
            &call_context_read_row_1,
            &call_context_read_row_2,
            &call_context_read_row_3,
        ]);

        let mut core_row_0 = ExecutionState::END_CALL.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // assign success, parent_call_id_inv and returndata_size
        // success为当前Call的执行结果
        // returndata_size为当前Call执行后返回的数据字节
        // parent_call_id_inv为父调用的CALLID，与parent_call_id结合使用SimpleZero，在约束
        // 时判断当前的调用是否为root call，为root call时，parent_call_id_inv与parent_call_id=0
        let success = U256::from(1);
        let parent_call_id_inv = U256::from_little_endian(
            F::from_u128(current_state.parent_call_id[&current_state.call_id] as u128)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            success
        );
        assign_or_panic!(
            core_row_0
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + PARENT_CALL_ID_INV_COL_IDX],
            parent_call_id_inv
        );
        assign_or_panic!(
            core_row_0
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + RETURNDATA_SIZE_COL_IDX],
            current_state.returndata_size
        );
        // 根据next exec state 填充core row0 的 下一个状态是POST_CALL(列29)还是EndTx(列28),分别在对应的列置为1
        match current_state.next_exec_state {
            Some(ExecutionState::POST_CALL) => {
                assign_or_panic!(
                    core_row_0[NUM_STATE_HI_COL
                        + NUM_STATE_LO_COL
                        + NUM_AUXILIARY
                        + END_CALL_NEXT_IS_POST_CALL],
                    U256::one()
                );
            }
            Some(ExecutionState::END_TX) => {
                assign_or_panic!(
                    core_row_0[NUM_STATE_HI_COL
                        + NUM_STATE_LO_COL
                        + NUM_AUXILIARY
                        + END_CALL_NEXT_IS_END_TX],
                    U256::one()
                );
            }
            _ => (),
        }
        // CALL调用结束后，非root call时恢复code_addr，call_id为父调用状态
        //update code_addr and call_id
        if current_state.parent_call_id[&current_state.call_id] != 0 {
            current_state.code_addr = current_state.parent_code_addr[&current_state.call_id];
            current_state.call_id = current_state.parent_call_id[&current_state.call_id];
        }

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                call_context_read_row_0,
                call_context_read_row_1,
                call_context_read_row_2,
                call_context_read_row_3,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EndCallGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::HashMap;
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint_with_parent_call() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            call_id: 80,
            code_addr: 0xbbbb.into(),
            parent_call_id: HashMap::new(),
            stack_pointer,
            parent_pc: HashMap::new(),
            parent_code_addr: HashMap::new(),
            parent_stack_pointer: HashMap::new(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.parent_call_id.insert(80, 1);
        current_state.parent_pc.insert(80, 100);
        current_state.parent_code_addr.insert(80, 0xaaaa.into());
        current_state.parent_stack_pointer.insert(80, 20);
        current_state.return_data.insert(80, [0x12; 4].to_vec());
        current_state.returndata_size = 4.into();

        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack); // end_call doesn't have opcode, like begin_tx_1 and begin_tx_2
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::RETURN_REVERT.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] = Some(4.into()); // let the previous gadgets(return_revert or stop)'s returndata_size cell's value equals to returndata_size
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::POST_CALL.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 100.into();
            row
        };
        current_state.next_exec_state = Some(ExecutionState::POST_CALL);
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }

    #[test]
    fn assign_and_constraint_without_parent_call() {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            call_id: 1,
            code_addr: 0xaaaa.into(),
            parent_call_id: HashMap::new(),
            stack_pointer,
            parent_pc: HashMap::new(),
            parent_code_addr: HashMap::new(),
            parent_stack_pointer: HashMap::new(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.parent_call_id.insert(1, 0);
        current_state.parent_pc.insert(1, 0);
        current_state.parent_code_addr.insert(1, 0.into());
        current_state.parent_stack_pointer.insert(1, 0);

        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack); // end_call doesn't have opcode, like begin_tx_1 and begin_tx_2
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::RETURN_REVERT.into_exec_state_core_row(
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
            let mut row = ExecutionState::END_TX.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 0.into();
            row
        };
        current_state.next_exec_state = Some(ExecutionState::END_TX);
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
