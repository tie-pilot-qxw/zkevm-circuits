use crate::execution::{
    begin_tx_2, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, copy, public, WitnessExecHelper};
use crate::witness::{state::CallContextTag, Witness};
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub const NUM_ROW: usize = 3;
const LEN_LO_INV_COL_IDX: usize = 11;
const TX_IDX_DELTA: i32 = 1;
pub struct BeginTx1Gadget<F: Field> {
    _marker: PhantomData<F>,
}

/// 每个交易初始阶段先执行BeginTx_1/2 gadget，设置一些辅助的状态变量
/// Begin_tx_1/2 非EVM Opcode指令，是zkEVM电路中内置的工具；
/// Begin_tx_1 负责设置将执行交易的tx_id和root call的call_id，
/// 记录交易的to地址或新建合约地址以及交易的calldata size，并设置
/// 父状态的地址和callid为0，标识为root call
///
///  
/// BeginTx1 Execution State layout is as follows
/// where STATE means state table lookup for writing call context,
/// COPY means copy table lookup,
/// PUBLIC means public table lookup (origin from col 26),
/// calldatasize_inv inverse of the calldata size in tx.
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY   | calldatasize_inv| PUBLIC  |
/// | 1 | STATE | STATE | STATE | STATE    |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BeginTx1Gadget<F>
{
    fn name(&self) -> &'static str {
        "BEGIN_TX_1"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BEGIN_TX_1
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, begin_tx_2::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        let copy = config.get_copy_lookup(meta, 0);
        let (_, _, _, _, _, _, _, _, _, copy_size, _) =
            extract_lookup_expression!(copy, copy.clone());
        let delta = AuxiliaryOutcome {
            // 记录了4个状态(to地址，calldata size, 父环境的code_addr和call_id)和
            // 从public calldata区域拷贝copy size大小的数据
            state_stamp: ExpressionOutcome::Delta(4.expr() + copy_size),
            stack_pointer: ExpressionOutcome::To(0.expr()),
            log_stamp: ExpressionOutcome::To(0.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let Auxiliary {
            state_stamp,
            refund,
            gas_left,
            ..
        } = config.get_auxiliary();
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let (_, _, storage_contract_addr_hi, storage_contract_addr_lo, _, _, _, _) =
            extract_lookup_expression!(state, config.get_state_lookup(meta, 0));
        let refund = meta.query_advice(refund, Rotation::cur());
        constraints.push(("init tx refund = 0".into(), refund));
        // 约束pc, tx_idx, call_id, code_addr为0
        let delta = CoreSinglePurposeOutcome {
            tx_idx: ExpressionOutcome::Delta(TX_IDX_DELTA.expr()),
            pc: ExpressionOutcome::To(0.expr()),
            call_id: ExpressionOutcome::To(state_stamp_prev.clone() + 1.expr()),
            code_addr: ExpressionOutcome::To(
                storage_contract_addr_hi * pow_of_two::<F>(128) + storage_contract_addr_lo,
            ),
        };
        constraints.append(&mut config.get_cur_single_purpose_constraints(meta, NUM_ROW, delta));
        constraints.append(
            &mut config
                .get_next_single_purpose_constraints(meta, CoreSinglePurposeOutcome::default()),
        );

        // begin_tx constraint
        constraints.append(&mut config.get_begin_tx_constrains(
            meta,
            NUM_ROW,
            call_id.clone(),
            &[
                CallContextTag::StorageContractAddr,
                CallContextTag::CallDataSize,
                CallContextTag::ParentCallId,
                CallContextTag::ParentCodeContractAddr,
            ],
        ));

        // 读取calldata size状态，因为128bit足以标识其大小，所以在get_copy_constraints仅约束value_lo
        let (_, _, value_hi, value_lo, _, _, _, _) =
            extract_lookup_expression!(state, config.get_state_lookup(meta, 1));
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let len_lo_inv = meta.query_advice(config.vers[LEN_LO_INV_COL_IDX], Rotation(-2));
        let is_zero_len = SimpleIsZero::new(&value_lo, &len_lo_inv, String::from("length_lo"));
        constraints.append(&mut is_zero_len.get_constraints());
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::PublicCalldata,
            tx_idx.clone(),
            0.expr(),
            0.expr(), // stamp is None for PublicCalldata
            copy::Tag::Calldata,
            call_id,
            0.expr(),
            state_stamp_prev.clone() + 4.expr(),
            None,
            value_lo,
            is_zero_len.expr(),
            None,
            copy,
        ));
        // 约束calldata size记录的高128bit为0
        constraints.push(("calldata size value_hi=0".into(), value_hi));

        // 获取4个state状态的操作数
        let mut operands = vec![];
        for i in 0..4 {
            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, config.get_state_lookup(meta, i));
            operands.push([value_hi, value_lo]);
        }
        // 因为为root call，所以约束parent call_id = 0
        constraints.extend([
            ("parent call_id hi=0".into(), operands[2][0].clone()),
            ("parent call_id lo=0".into(), operands[2][1].clone()),
        ]);

        // 因为为root call，所以约束parent code_addr = 0
        constraints.extend([
            ("parent code_addr hi=0".into(), operands[3][0].clone()),
            ("parent code_addr lo=0".into(), operands[3][1].clone()),
        ]);

        //约束public entry 与state entry记录的calldata size和code_addr状态一致
        let public_entry = config.get_public_lookup(meta, 0);
        config.get_public_constraints(
            meta,
            public_entry,
            (public::Tag::TxToCallDataSize as u8).expr(),
            Some(tx_idx.clone()),
            [
                // constraint storage_contract_addr hi == tx.to hi
                Some(operands[0][0].clone()),
                // constraint storage_contract_addr lo == tx.to lo
                Some(operands[0][1].clone()),
                // constraint calldata_size hi == 0
                Some(operands[1][0].clone()),
                // constraint calldata_size lo == tx.input.len
                Some(operands[1][1].clone()),
            ],
        );

        let gas_left = meta.query_advice(gas_left, Rotation::cur());
        let public_entry = config.get_public_lookup(meta, 1);
        config.get_public_constraints(
            meta,
            public_entry,
            (public::Tag::TxGasLimit as u8).expr(),
            Some(tx_idx),
            [Some(gas_left), None, None, None],
        );

        // next state constraints
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                // 约束下一个状态为begin_tx_2
                vec![(ExecutionState::BEGIN_TX_2, begin_tx_2::NUM_ROW, None)],
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
        // 从core电路的 core_row_1行中获取4个state 数据，与state电路进行lookup
        let state_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let state_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let state_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let state_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        // 从core电路的 core_row_2行获取copy数据，core电路与copy电路lookup
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        // 从core电路的 core_row_2行获取public数据，core电路与public电路lookup
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        let public_gas_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 1));
        vec![
            ("contract addr write".into(), state_lookup_0),
            ("calldata size write".into(), state_lookup_1),
            ("parent call_id write".into(), state_lookup_2),
            ("parent code addr write".into(), state_lookup_3),
            ("copy lookup".into(), copy_lookup),
            ("public lookup".into(), public_lookup),
            ("public gas lookup".into(), public_gas_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let call_id = current_state.state_stamp + 1;
        // update call_id and tx_idx due to will be accessed in get_write_call_context_row
        // 设置将执行交易的call_id和tx_idx；Note：tx_idx从1开始
        current_state.call_id = call_id;
        current_state.tx_idx += 1;

        // 记录交易的to地址或 创建合约交易新创建的合约地址
        let addr = current_state.code_addr;
        let write_addr_row = current_state.get_write_call_context_row(
            Some((addr >> 128).as_u128().into()),
            Some(addr.low_u128().into()),
            CallContextTag::StorageContractAddr,
            None,
        );
        // 记录交易的calldata size
        let calldata_size = current_state
            .call_data
            .get(&call_id)
            .map(|v| v.len())
            .unwrap_or_default();
        let write_calldata_size_row = current_state.get_write_call_context_row(
            None,
            Some(calldata_size.into()),
            CallContextTag::CallDataSize,
            None,
        );
        // 记录当前的call_id的父调用为0，标识它为root call
        current_state
            .parent_call_id
            .insert(current_state.call_id, 0);
        let write_parent_call_id_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            CallContextTag::ParentCallId,
            None,
        );
        // 记录当前的call_id的父合约地址为0，标识它为root call
        current_state
            .parent_code_addr
            .insert(current_state.call_id, 0.into());
        let write_parent_code_addr_row = current_state.get_write_call_context_row(
            None,
            Some(0.into()),
            CallContextTag::ParentCodeContractAddr,
            None,
        );
        // 从交易的calldata区域copy数据至root call的calldata
        let (copy_rows, state_rows_from_copy) = if calldata_size > 0 {
            current_state.get_load_calldata_copy_rows::<F>()
        } else {
            (vec![], vec![])
        };
        // 生成core_row_2，写入copy的数据
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        if calldata_size > 0 {
            core_row_2.insert_copy_lookup(0, copy_rows.first().unwrap());
        } else {
            // no actually copy, but we need to insert same format placeholders to satisfy constraint
            core_row_2.insert_copy_lookup(
                0,
                &copy::Row {
                    byte: 0.into(), //not used
                    src_type: copy::Tag::Zero,
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Zero,
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: 0.into(), //not used
                    len: 0.into(),
                    acc: 0.into(),
                },
            );
        }

        // core_row_2写入calldata size的相反数，用于在约束时判断长度为0的情况
        let len_lo = F::from_u128(calldata_size as u128);
        let len_lo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        assign_or_panic!(core_row_2[LEN_LO_INV_COL_IDX], len_lo_inv);

        // core_row_2写入交易的calldata size和to 地址，与public电路lookup
        let public_row = current_state.get_public_tx_row(public::Tag::TxToCallDataSize, 0);
        core_row_2.insert_public_lookup(0, &public_row);
        let public_row = current_state.get_public_tx_row(public::Tag::TxGasLimit, 1);
        core_row_2.insert_public_lookup(1, &public_row);

        // core_row_1写入交易的4个状态（to地址或创建的合约地址，交易的calldata_size，父call_id和code_addr）
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([
            &write_addr_row,
            &write_calldata_size_row,
            &write_parent_call_id_row,
            &write_parent_code_addr_row,
        ]);
        let core_row_0 = ExecutionState::BEGIN_TX_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        let mut state = vec![
            write_addr_row,
            write_calldata_size_row,
            write_parent_call_id_row,
            write_parent_code_addr_row,
        ];
        state.extend(state_rows_from_copy);

        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BeginTx1Gadget {
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
        let call_data = HashMap::from([(call_id, vec![0xa, 0xb])]);
        let mut call_data_size = HashMap::new();
        call_data_size.insert(call_id, call_data[&call_id].len().into());
        let code_addr = U256::from(0x1234);
        let mut storage_contract_addr = HashMap::new();
        storage_contract_addr.insert(call_id, code_addr);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_id,
            call_data,
            call_data_size,
            code_addr,
            storage_contract_addr,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack);
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
            ExecutionState::BEGIN_TX_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            )
        };
        // padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row); //todo change begin row too
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
