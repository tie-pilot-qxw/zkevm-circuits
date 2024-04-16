use crate::execution::{
    begin_tx_3, AuxiliaryOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget,
    ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{public, WitnessExecHelper};
use crate::witness::{state::CallContextTag, Witness};
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;

pub struct BeginTx2Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// 每个交易初始阶段先执行BeginTx_1/2 gadget，设置一些辅助的状态变量
/// Begin_tx_1/2 非EVM Opcode指令，是zkEVM电路中内置的工具；
/// Begin_tx_2 负责设置将执行交易的tx_id和root call的call_id，
/// 记录交易的sender地址和value金额，并设置父状态的parent stack pointer
/// 和parent pc为0，标识为root call
///  
/// BeginTx2 Execution State layout is as follows
/// where STATE means state table lookup for writing call context,
/// PUBLIC means public table lookup (origin from col 26),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 |                         | PUBLIC |
/// | 1 | STATE | STATE | STATE | STATE    |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginTx2Gadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_TX_2"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_TX_2
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, begin_tx_3::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        // auxiliary and single purpose constraints
        let delta = AuxiliaryOutcome {
            // 记录了4个state状态
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            // 目前gas,refund的约束还没启用
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        let delta = Default::default();
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));
        // begin_tx constraints
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        constraints.append(&mut config.get_begin_tx_constrains(
            meta,
            NUM_ROW,
            call_id,
            &[
                CallContextTag::SenderAddr,
                CallContextTag::Value,
                CallContextTag::ParentProgramCounter,
                CallContextTag::ParentStackPointer,
            ],
        ));

        // 记录4个状态的操作数
        let mut operands = vec![];
        for i in 0..4 {
            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, config.get_state_lookup(meta, i));
            operands.push([value_hi, value_lo]);
        }

        // constraint parent pc = 0
        constraints.extend([
            ("parent pc hi=0".into(), operands[2][0].clone()),
            ("parent pc lo=0".into(), operands[2][1].clone()),
        ]);

        // constraint stack pointer = 0
        constraints.extend([
            ("parent stack pointer hi=0".into(), operands[3][0].clone()),
            ("parent stack pointer lo=0".into(), operands[3][1].clone()),
        ]);

        //constraint public lookup
        let tx_id = meta.query_advice(config.tx_idx, Rotation::cur());
        let public_entry = config.get_public_lookup(meta, 0);
        config.get_public_constraints(
            meta,
            public_entry,
            (public::Tag::TxFromValue as u8).expr(),
            Some(tx_id),
            [
                Some(operands[0][0].clone()), // constraint sender_addr hi == tx.from hi
                Some(operands[0][1].clone()), // constraint sender_addr lo == tx.from lo
                Some(operands[1][0].clone()), // constraint value hi == tx.value hi
                Some(operands[1][1].clone()), // constraint value lo == tx.value lo
            ],
        );

        // prev state constraint
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::BEGIN_TX_1],
                NUM_ROW,
                vec![(ExecutionState::BEGIN_TX_3, begin_tx_3::NUM_ROW, None)],
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
        // 从core电路中读取记录的4个state状态，与state 电路进行lookup
        let state_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let state_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let state_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let state_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        // 从core电路中读取public状态，与public电路进行lookup
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));

        vec![
            ("value write".into(), state_lookup_0),
            ("sender addr write".into(), state_lookup_1),
            ("parent pc write".into(), state_lookup_2),
            ("parent stack pointer write".into(), state_lookup_3),
            ("public lookup".into(), public_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let call_id = current_state.call_id;
        let value = *current_state.value.get(&call_id).unwrap();
        let sender = *current_state.sender.get(&call_id).unwrap();
        // 记录交易的发送者 from
        let write_sender_row = current_state.get_write_call_context_row(
            Some((sender >> 128).as_u128().into()),
            Some(sender.low_u128().into()),
            CallContextTag::SenderAddr,
            None,
        );
        // 交易的eth金额 value
        let write_value_row = current_state.get_write_call_context_row(
            Some((value >> 128).as_u128().into()),
            Some(value.low_u128().into()),
            CallContextTag::Value,
            None,
        );
        // 更新root call的parent pc为0，并记录相关状态
        current_state.parent_pc.insert(current_state.call_id, 0);
        let write_parent_pc_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            CallContextTag::ParentProgramCounter,
            None,
        );
        // root call的parent stack pointer为0，并记录相关状态
        current_state
            .parent_stack_pointer
            .insert(current_state.call_id, 0);
        let write_parent_stack_pointer_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            CallContextTag::ParentStackPointer,
            None,
        );

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // 记录交易的from、value状态
        let public_row = current_state.get_public_tx_row(public::Tag::TxFromValue, 0);
        core_row_2.insert_public_lookup(0, &public_row);

        // core_row_1 写入4个state row状态
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([
            &write_sender_row,
            &write_value_row,
            &write_parent_pc_row,
            &write_parent_stack_pointer_row,
        ]);
        let core_row_0 = ExecutionState::BEGIN_TX_2.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![
                write_sender_row,
                write_value_row,
                write_parent_pc_row,
                write_parent_stack_pointer_row,
            ],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginTx2Gadget {
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
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let stack_pointer = stack.0.len();
        let call_id = 1;
        let value = HashMap::from([(call_id, 0xaaaaaa.into())]);
        let sender = HashMap::from([(call_id, 0xfffffff.into())]);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_id,
            value,
            sender,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
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
            ExecutionState::BEGIN_TX_3.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        // padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
