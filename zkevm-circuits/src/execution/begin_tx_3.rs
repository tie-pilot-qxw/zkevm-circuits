use crate::arithmetic_circuit::operation;
use crate::constant::{BLOCK_IDX_LEFT_SHIFT_NUM, GAS_LEFT_IDX};
use crate::execution::{
    AuxiliaryOutcome, ExecStateTransition, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, public, WitnessExecHelper};
use crate::witness::{state::CallContextTag, Witness};
use eth_types::evm_types::{GasCost, INIT_CODE_WORD_GAS};
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
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
/// PUBLIC Tag is TxIsCreateCallDataGasCost, include is create, call data gas cost
/// Arithmetic_tiny is ((call_data_length + 31) / 32)
/// +-----+-----------------------+-------------------------+
/// | cnt |                       |                         |
/// +-----+-----------------------+-------------------------+
/// | 2   | PUBLIC(0..5)          | Arithmetic_tiny(7..11)  |
/// | 1   | STATE0(0..7)          | STATE(8..15)            |
/// | 0   | DYNA_SELECTOR(0..17)  | AUX(18..24)             |
/// +-----+-----------------------+-------------------------+
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());
        let block_tx_idx =
            (block_idx.clone() * (1u64 << BLOCK_IDX_LEFT_SHIFT_NUM).expr()) + tx_idx.clone();

        // auxiliary and single purpose constraints
        let (gas_cost, gas_constraints) =
            get_intrinsic_gas_cost(config, meta, block_tx_idx.clone());
        constraints.extend(gas_constraints);
        // auxiliary and single purpose constraints
        let delta = AuxiliaryOutcome {
            // 记录了2个state状态
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
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
        let public_intrinsic_gas_cost =
            query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        // 从core电路中读取arithmetic状态，与arithmetic电路进行lookup
        let arithmetic_lookup =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        vec![
            ("default return data call id write".into(), state_lookup_0),
            ("default return data size write".into(), state_lookup_1),
            (
                "public intrinsic gas cost lookup".into(),
                public_intrinsic_gas_cost,
            ),
            ("arithmetic lookup".into(), arithmetic_lookup),
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
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let public_row = current_state.get_public_tx_is_create_row();
        core_row_2.insert_public_lookup(0, &public_row);
        let call_data_len = current_state
            .call_data_size
            .get(&current_state.call_id)
            .unwrap_or(&U256::zero())
            .clone();
        let (arithmetic_row, _) =
            operation::memory_expansion::gen_witness(vec![call_data_len, 0.into()]);
        core_row_2.insert_arithmetic_tiny_lookup(0, &arithmetic_row);

        // core_row_1 写入2个state row状态, returndata_call_id 和 returndata_size
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([
            &default_returndata_call_id_row,
            &default_returndata_size_row,
        ]);
        let mut core_row_0 = ExecutionState::BEGIN_TX_3.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let gas_cost = intrinsic_gas_cost(current_state, call_data_len);
        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
            Some(U256::from(current_state.gas_left - gas_cost));

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![default_returndata_call_id_row, default_returndata_size_row],
            arithmetic: arithmetic_row,
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

fn get_intrinsic_gas_cost<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    meta: &mut VirtualCells<F>,
    block_tx_idx: Expression<F>,
) -> (Expression<F>, Vec<(String, Expression<F>)>) {
    let mut constraints = vec![];
    let public_entry = config.get_public_lookup(meta, 0);
    let (_, _, [is_create, call_data_gas_cost, _, _]) =
        extract_lookup_expression!(public, public_entry.clone());

    let arithmetic_entry = config.get_arithmetic_tiny_lookup(meta, 0);
    let (tag, [_, _, _, call_data_word_length]) =
        extract_lookup_expression!(arithmetic_tiny, arithmetic_entry);

    constraints.extend(config.get_public_constraints(
        meta,
        public_entry,
        (public::Tag::TxIsCreateAndStatus as u8).expr(),
        Some(block_tx_idx.clone()),
        [None, None, None, None],
    ));

    constraints.push((
        "arithmetic tag = MemoryExpansion".into(),
        tag - (arithmetic::Tag::MemoryExpansion as u8).expr(),
    ));

    let init_code_gas_cost = select::expr(
        is_create.clone(),
        call_data_word_length * INIT_CODE_WORD_GAS.expr(),
        0.expr(),
    );

    let intrinsic_gas_cost = select::expr(
        is_create.clone(),
        GasCost::CREATION_TX.expr(),
        GasCost::TX.expr(),
    ) + call_data_gas_cost
        + init_code_gas_cost;

    (intrinsic_gas_cost, constraints)
}

pub fn intrinsic_gas_cost(current_state: &mut WitnessExecHelper, call_data_len: U256) -> u64 {
    let init_code_gas_cost = (call_data_len + 31) / 32 * INIT_CODE_WORD_GAS;
    let is_create = current_state.is_create as u64;

    let intrinsic_gas_cost = is_create * (init_code_gas_cost.as_u64() + GasCost::CREATION_TX)
        + (1 - is_create) * GasCost::TX
        + current_state.call_data_gas_cost();
    intrinsic_gas_cost
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
            gas_left: 0x254023,
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
