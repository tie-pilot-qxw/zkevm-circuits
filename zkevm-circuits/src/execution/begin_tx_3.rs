use crate::execution::{
    AuxiliaryOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::WitnessExecHelper;
use crate::witness::{state::CallContextTag, Witness};
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;

pub struct BeginTx3Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// 每个交易初始阶段先执行BeginTx_1/2 gadget，设置一些辅助的状态变量
/// Begin_tx_1/2/3 非EVM Opcode指令，是zkEVM电路中内置的工具；
/// Begin_tx_2 负责设置将执行交易的tx_id和root call的call_id，
/// Begin_tx_3 负责设置默认的return_data_call_id和return_data_size
/// BeginTx3 Execution State layout is as follows
/// where STATE means state table lookup for writing default
/// return_data_call_id and return_data_size
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE | STATE |       |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginTx3Gadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_TX_3"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_TX_3
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
        let mut constraints = vec![];
        // auxiliary and single purpose constraints
        let delta = AuxiliaryOutcome {
            // 记录了2个state状态
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        let delta = Default::default();
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));
        // begin_tx constraints
        constraints.append(&mut config.get_begin_tx_constrains(
            meta,
            NUM_ROW,
            0.expr(),
            &[
                CallContextTag::ReturnDataCallId,
                CallContextTag::ReturnDataSize,
            ],
        ));

        // 记录2个状态的操作数
        let mut operands = vec![];
        for i in 0..2 {
            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, config.get_state_lookup(meta, i));
            operands.push([value_hi, value_lo]);
        }

        // constraint default return data call id = 0
        constraints.extend([
            ("return_data_call_id_hi=0".into(), operands[0][0].clone()),
            ("return_data_call_id_lo=0".into(), operands[0][1].clone()),
        ]);

        // constraint default return data size  = 0
        constraints.extend([
            ("return_data_size_hi=0".into(), operands[1][0].clone()),
            ("return_data_size_lo=0".into(), operands[1][1].clone()),
        ]);

        // prev state constraint
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(vec![ExecutionState::BEGIN_TX_2], NUM_ROW, vec![], None),
        ));
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // 从core电路中读取记录的2个state状态，与state 电路进行lookup
        let state_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let state_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        vec![
            ("default return data call id write".into(), state_lookup_0),
            ("default return data size write".into(), state_lookup_1),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 生成默认的returndata_call_id 行
        let default_returndata_call_id_row = current_state.get_returndata_call_id_row(true);
        let default_returndata_size_row = current_state.get_write_call_context_row(
            Some((current_state.returndata_size >> 128).as_u128().into()),
            Some(current_state.returndata_size.low_u128().into()),
            CallContextTag::ReturnDataSize,
            Some(current_state.returndata_call_id.into()),
        );
        // core_row_1 写入2个state row状态, returndata_call_id 和 returndata_size
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([
            &default_returndata_call_id_row,
            &default_returndata_size_row,
        ]);
        let core_row_0 = ExecutionState::BEGIN_TX_3.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![default_returndata_call_id_row, default_returndata_size_row],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginTx3Gadget {
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
            let mut row = ExecutionState::BEGIN_TX_2.into_exec_state_core_row(
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
            ExecutionState::END_PADDING.into_exec_state_core_row(
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
