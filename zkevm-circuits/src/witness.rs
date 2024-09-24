// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::io::Write;

use halo2_proofs::halo2curves::bn256::Fr;
use serde::Serialize;

use eth_types::error::GethExecError;
use eth_types::evm_types::{OpcodeId, MAX_CODE_SIZE};
use eth_types::geth_types::{ChunkData, GethData};
use eth_types::{Bytecode, Field, GethExecStep, StateDB, Word, U256};
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use gadgets::simple_seletor::simple_selector_assign;

use crate::arithmetic_circuit::{operation, ArithmeticCircuit};
use crate::bitwise_circuit::BitwiseCircuit;
use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{
    ARITHMETIC_COLUMN_WIDTH, ARITHMETIC_TINY_COLUMN_WIDTH, ARITHMETIC_TINY_START_IDX,
    BITWISE_COLUMN_START_IDX, BITWISE_COLUMN_WIDTH, BIT_SHIFT_MAX_IDX, BLOCK_IDX_LEFT_SHIFT_NUM,
    BYTECODE_COLUMN_START_IDX, BYTECODE_NUM_PADDING, COPY_LOOKUP_COLUMN_CNT, DESCRIPTION_AUXILIARY,
    EXP_COLUMN_START_IDX, LOG_SELECTOR_COLUMN_START_IDX, MAX_CODESIZE, MAX_NUM_ROW,
    MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH, NUM_STATE_HI_COL, NUM_STATE_LO_COL, NUM_VERS,
    PUBLIC_COLUMN_START_IDX, PUBLIC_COLUMN_WIDTH, PUBLIC_NUM_VALUES, STAMP_CNT_COLUMN_START_IDX,
    STATE_COLUMN_WIDTH, STORAGE_COLUMN_WIDTH,
};
use crate::copy_circuit::CopyCircuit;
use crate::core_circuit::CoreCircuit;
use crate::error::{get_step_reported_error, DepthError, ExecError};
use crate::execution::{get_every_execution_gadgets, ExecutionGadget, ExecutionState};
use crate::exp_circuit::ExpCircuit;
use crate::keccak_circuit::keccak_packed_multi::{calc_keccak, calc_keccak_hi_lo};
use crate::public_circuit::PublicCircuit;
use crate::state_circuit::ordering::state_to_be_limbs;
use crate::state_circuit::StateCircuit;
use crate::util::{
    convert_f_to_u256, convert_u256_to_f, create_contract_addr_with_prefix, SubCircuit,
};
use crate::witness::public::{public_rows_to_instance, LogTag};
use crate::witness::state::{CallContextTag, Tag};
use crate::witness::util::{extract_address_from_tx, handle_sstore};

pub mod arithmetic;
pub mod bitwise;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fixed;
pub mod public;
pub mod state;
mod util;

#[derive(Debug, Default, Clone)]
pub struct Witness {
    pub bytecode: Vec<bytecode::Row>,
    pub copy: Vec<copy::Row>,
    pub core: Vec<core::Row>,
    pub exp: Vec<exp::Row>,
    pub public: Vec<public::Row>,
    pub state: Vec<state::Row>,
    pub arithmetic: Vec<arithmetic::Row>,
    pub bitwise: Vec<bitwise::Row>,
    // keccak inputs, Keccak needs to use challenge to calculate the RLC value, and challenge can
    // only be used inside the circuit,so all the inputs that need to be calculated hash are saved here,
    // and then keccak_circuit will calculate rows based on the inputs in the synthesize_sub method inside the circuit.
    pub keccak: Vec<Vec<u8>>,
    // we omit fixed table rows on purpose due to its large size
}
#[derive(Debug, Default, Clone)]
pub struct WitnessExecHelper {
    pub stack_pointer: usize,
    // 存储CALL指令的父环境stack_pointer值，如在CALL调用中，key==即将执行的CALL_ID，value=父环境的stack_pointer值
    // 每次执行新的CALL，stack_pointer会重置为0.
    pub parent_stack_pointer: HashMap<u64, usize>,
    // 记录CALL对应的calldata；如在CALL调用中，key=执行的CALL_ID，value=该CALL对应的calldata
    pub call_data: HashMap<u64, Vec<u8>>,
    // 记录CALL对应的call_data_gas_cost, 与call_data插入数据时机相同，提前计算并保存，不需要每次调用循环计算
    pub call_data_gas_cost: HashMap<u64, u64>,
    // 记录CALL对应的calldata大小；如在CALL调用中，key=执行的CALL_ID，value=该CALL对应操作数args_length，
    // 也是执行的CALL指令的calldata size
    pub call_data_size: HashMap<u64, U256>,
    pub return_data: HashMap<u64, Vec<u8>>,
    // 记录CALL对应的eth金额；如在CALL调用中，key=即将执行的CALL_ID，value=该CALL对应的eth amount
    pub value: HashMap<u64, U256>,
    // 存储调用方地址；如在CALL调用中，key=即将执行的CALL_ID，value=执行该CALL指令的调用方合约地址
    pub sender: HashMap<u64, U256>,
    // 当前区块的索引. Note: 从1开始.
    pub block_idx: usize,
    // 当前交易在区块的索引，Note：从1开始
    pub tx_idx: usize,
    // chunk 内 block 的数量
    pub block_num_in_chunk: usize,
    // 区块内交易的数量, key: block_idx, value: tx_num
    pub tx_num_in_block: HashMap<usize, usize>,
    // 区块 log 的数量, key: block_idx, value: log_num
    pub log_num_in_block: HashMap<usize, usize>,
    // 正在执行的call_id
    pub call_id: u64,
    // 下一个即将执行的call id；如在执行evm CALL指令时，将生成的新call id赋值该字段，
    // 用于进行上下文数据的存储（call_id，storage_contract_addr），方便调用结束后
    // 恢复调用方状态
    pub call_id_new: u64,
    // 存储CALL指令的父环境CALL_ID，如在CALL调用中，key=即将执行的CALL_ID，value=父环境的CALL_ID
    pub parent_call_id: HashMap<u64, u64>,
    pub returndata_call_id: u64,
    pub returndata_size: U256,
    pub return_success: bool,
    // 正在执行的合约地址
    pub code_addr: U256,
    // 存储父合约地址；如在CALL调用中，key=即将执行的CALL_ID，value=执行该CALL指令的调用方合约地址
    pub parent_code_addr: HashMap<u64, U256>,
    // 存储执行的合约地址，与sender字段相反；如在CALL调用中，key=即将执行的CALL_ID，value=CALL指令将执行的合约地址
    pub storage_contract_addr: HashMap<u64, U256>,
    pub state_stamp: u64,
    pub log_stamp: u64,
    // gas_left默认存储的是执行完当前状态后的剩余gas
    // 对于类似CALL指令这种特殊的gas，会在CALL gen_witness时单独进行修改
    pub gas_left: u64,
    pub refund: u64,
    pub memory_chunk: u64,
    pub parent_memory_chunk: HashMap<u64, u64>,
    pub memory_chunk_prev: u64,
    pub read_only: u64,
    pub bytecode: HashMap<U256, Bytecode>,
    /// The stack top of the next step, also the result of this step
    pub stack_top: Option<U256>,
    pub topic_left: usize,
    // used to temporarily store the results of sar1 calculations for use by sar2 (shr result and sign bit)
    pub sar: Option<(U256, U256)>,
    pub tx_value: U256,
    // 存储CALL指令的父环境PC值，如在CALL调用中，key==即将执行的CALL_ID，value=父环境的PC值
    pub parent_pc: HashMap<u64, u64>,
    pub state_db: StateDB,
    pub is_create: bool,
    // 存储下一个指令的第一个状态
    pub next_exec_state: Option<ExecutionState>,
    // 暂存call指令的memory_gas_cost
    pub memory_gas_cost: u64,
    // 存储父环境的trace.gas
    pub parent_gas: HashMap<u64, u64>,
    // 存储父环境的trace.gas_cost
    pub parent_gas_cost: HashMap<u64, u64>,
    // 暂存上一步的memory_size, 对应EVM中的memoryFunc的传参，是由stack中的值决定的，用于memory gas计算
    pub new_memory_size: Option<u64>,
    // 暂存上一步stack中的length值，用于memory gas计算
    pub length_in_stack: Option<u64>,
    // 存储当前 chunk 的第一个区块的 number
    pub block_number_first_block: u64,
    // 存储当前 block 的 TIMESTAMP
    pub timestamp: U256,
    // 存储当前 block 的 COINBASE
    pub coinbase: U256,
    // 存储当前 block 的 GASLIMIT
    pub block_gaslimit: U256,
    // 存储当前 block 的 BASEFEE
    pub basefee: U256,
    // 存储当前 block 的 PREVRANDAO (mix hash)
    pub prevrandao: U256,
    // 存储当前 tx 的 GASLIMIT
    pub tx_gaslimit: U256,
    // 存储当前 tx 的 gasprice
    pub tx_gasprice: U256,
    // 存储当前的 ChainID
    pub chain_id: U256,
    // callTrace 中读取到的变量，初始化后该值不会发生变化
    pub call_is_success: Vec<bool>,
    // CALLX, CREATEX 的次数，递增的值，不会减小
    pub call_cnt: usize,
    // call_is_success的偏移量，当is_precheck_not_ok+1, 递增值
    pub call_is_success_offset: usize,
    // call是否调用成功的上下文，主要用于获取next_is_success, 可增可减，遇到return等命令会返回
    pub call_ctx: Vec<CallInfoContext>,
    // 存储临时值，只作用于当前交易，交易结束会被清空
    pub transient_storage: HashMap<U256, U256>,
}

#[derive(Debug, Default, Clone)]
pub struct CallInfoContext {
    pub is_success: bool,
    pub is_static: bool,
}

impl WitnessExecHelper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_block_tx_idx(&self) -> usize {
        (self.block_idx << BLOCK_IDX_LEFT_SHIFT_NUM) + self.tx_idx
    }

    pub fn update_from_next_step(&mut self, trace: &GethExecStep) {
        self.stack_top = trace.stack.0.last().cloned();
        // 更新一下下一个指令的第一个状态
        self.next_exec_state = ExecutionState::from_opcode(trace.op).first().copied();
    }

    /// 计算call_data花费的gas，byte为0时是4， 非0 为16
    pub fn call_data_gas_cost(&self) -> u64 {
        *self.call_data_gas_cost.get(&self.call_id).unwrap_or(&0)
    }

    /// stack_pointer decrease
    pub fn stack_pointer_decrease(&mut self) {
        self.stack_pointer -= 1;
    }

    /// 主要分为两部，第一步是为了找到上一个区块的对应的key/value，填充original_storage;
    /// 第二步是获取每一笔交易的最后一次sstore的值，填充pending_storage;
    pub fn preprocess_storage(&mut self, geth_data: &GethData) {
        self.handle_committed_value(geth_data);
        self.handle_last_sstore(geth_data);
    }

    /// 直接获取每个account中的storage值
    fn handle_committed_value(&mut self, geth_data: &GethData) {
        // for account in geth_data.accounts.iter() {
        for account in geth_data.accounts.iter() {
            account.storage.iter().for_each(|(key, value)| {
                self.state_db
                    .insert_original_storage(account.address, *key, *value)
            });
        }
    }

    /// 倒序遍历，交易从0..n-1，每笔交易最后一次sstore的值，会存放到pending_sstore中
    fn handle_last_sstore(&mut self, geth_data: &GethData) {
        for (i, trace) in geth_data.geth_traces.iter().enumerate() {
            for step in trace.struct_logs.iter().rev() {
                if step.op == OpcodeId::SSTORE {
                    let to = extract_address_from_tx(geth_data, i);
                    // current_state 中的是从1开始计数，所以这里要加1
                    handle_sstore(to, step, &mut self.state_db, i + 1);
                }
            }
        }
    }

    pub fn initialize_each_block(&mut self) {
        self.state_db = StateDB::new();
        self.value = HashMap::new();
        self.tx_value = 0.into();
        self.sender = HashMap::new();
        self.code_addr = 0.into();
        self.storage_contract_addr = HashMap::new();
        self.bytecode = HashMap::new();
        self.gas_left = 0;
        self.is_create = false;
        self.memory_chunk = 0;
        self.memory_chunk_prev = 0;
        self.call_id = 0;
        self.call_id_new = 0;
        self.tx_idx = 0;
        self.stack_pointer = 0;
        self.parent_stack_pointer = HashMap::new();
        self.parent_memory_chunk = HashMap::new();
        self.stack_top = None;
        self.parent_pc = HashMap::new();
        self.parent_call_id = HashMap::new();
        self.returndata_call_id = 0;
        self.returndata_size = 0.into();
        self.log_stamp = 0;
        self.parent_gas = HashMap::new();
        self.memory_gas_cost = 0;
        self.parent_gas_cost = HashMap::new();
        self.call_data = HashMap::new();
        self.call_data_gas_cost = HashMap::new();
        self.call_data_size = HashMap::new();
        self.return_data = HashMap::new();
        self.parent_code_addr = HashMap::new();
        self.refund = 0;
        self.topic_left = 0;
        self.sar = None;
        self.next_exec_state = None;
        self.new_memory_size = None;
        self.length_in_stack = None;
        self.is_create = false;
    }

    pub fn initialize_each_tx(&mut self) {
        self.parent_stack_pointer = HashMap::new();
        self.parent_memory_chunk = HashMap::new();
        self.stack_top = None;
        self.parent_pc = HashMap::new();
        self.stack_pointer = 0;
        self.returndata_call_id = 0;
        self.returndata_size = 0.into();
        self.return_success = false;
        self.memory_chunk = 0;
        self.memory_chunk_prev = 0;
        self.state_db.reset_tx();
        self.transient_storage = HashMap::new();
    }

    /// Generate witness of one transaction's trace
    fn generate_trace_witness(
        &mut self,
        geth_data: &GethData,
        tx_idx: usize,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) -> Witness {
        // tx_idx counts from 1.
        let index = tx_idx - 1;
        let trace = &geth_data.geth_traces.get(index).unwrap().struct_logs;
        let tx = geth_data
            .eth_block
            .transactions
            .get(index)
            .expect("tx_idx out of bounds");
        let call_id = self.state_stamp + 1;
        self.call_id = call_id;

        let call_is_success = geth_data
            .geth_traces
            .get(index)
            .unwrap()
            .call_trace
            .gen_call_is_success();
        self.call_is_success = call_is_success;

        self.call_cnt = 1;
        let call = CallInfoContext {
            is_success: !geth_data.geth_traces.get(index).unwrap().failed,
            is_static: false,
        };
        self.call_ctx = vec![call];
        self.call_is_success_offset = 0;
        // due to we decide to start idx at 1 in witness
        // if contract-create tx, calculate `to`, else convert `to`
        let to = tx.to.map_or_else(
            || create_contract_addr_with_prefix(&tx),
            |to| to.as_bytes().into(),
        );
        // get bytecode: find all account.code and its address and create a map for them
        let mut bytecode = HashMap::new();
        for account in geth_data.accounts.iter() {
            bytecode.insert(account.address, Bytecode::from(account.code.to_vec()));
        }
        // add calldata to current_state
        self.call_data.insert(call_id, tx.input.to_vec());
        self.call_data_size.insert(call_id, tx.input.len().into());
        self.call_data_gas_cost.insert(
            call_id,
            eth_types::geth_types::Transaction::from(tx).call_data_gas_cost(),
        );

        self.value.insert(call_id, tx.value);
        self.tx_value = tx.value;
        self.sender.insert(call_id, tx.from.as_bytes().into());
        self.code_addr = to;
        self.storage_contract_addr.insert(call_id, to);
        self.bytecode = bytecode;
        self.gas_left = tx.gas.as_u64();
        self.is_create = tx.to.is_none();
        self.tx_idx = tx_idx;
        self.tx_gaslimit = tx.gas;
        self.tx_gasprice = tx.gas_price.unwrap_or(0.into());

        let mut res: Witness = Default::default();
        let first_step = trace.first().unwrap(); // not actually used in BEGIN_TX_1 and BEGIN_TX_2 and BEGIN_TX_3
        let last_step = trace.last().unwrap(); // not actually used in END_CALL and END_TX
        self.next_exec_state = Some(ExecutionState::BEGIN_TX_2);
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_1)
                .unwrap()
                .gen_witness(first_step, self),
        );
        let mut iter_for_next_step = trace.iter();
        let first_trace = iter_for_next_step.next();

        self.next_exec_state = Some(ExecutionState::BEGIN_TX_3);
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_2)
                .unwrap()
                .gen_witness(first_step, self),
        );
        match first_trace {
            Some(first_trace) => {
                self.next_exec_state = ExecutionState::from_opcode(first_trace.op).first().copied();
            }
            None => (),
        }
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_3)
                .unwrap()
                .gen_witness(first_step, self),
        );

        let mut prev_is_return_revert_or_stop = false;
        let mut call_step_store: Vec<&GethExecStep> = vec![];
        let mut prev_step_is_error = false;
        for step in trace {
            let next_step = iter_for_next_step.next();
            let need_exit_call = prev_step_is_error
                && matches!(self.next_exec_state, Some(ExecutionState::POST_CALL_1));

            if prev_is_return_revert_or_stop || need_exit_call {
                // append POST_CALL when the previous opcode is RETURN, REVERT or STOP which indicates the end of the lower-level call (this doesn't append POST_CALL at the end of the top-level call, because the total for-loop has ended)
                let call_trace_step = call_step_store.pop().unwrap();
                // 如果调用到POST_CALL,说明在CALL的流程并准备结束，此时POST_CALL的gas应该与CALL opcode时的gas保持一致，也即step.gas
                // 假设trace操作为：
                // CALL --------- (1)
                // PUSH1 1 ------ (2)
                // STOP --------- (3)
                // PUSH1 2 ------ (4)
                // 当CALL指令时，call_step_store push CALL此时的step；
                // 当STOP指令时，call_step_store pop CALL此时的step，即(1)时的状态；
                // 当执行到(4)时，实际上会先进入到POST_CALL，我们希望POST_CALL的gas_left应该为(4)的gas，也即step.gas
                // 由于CALL指令gas计算比较复杂，POST_CALL的gas_left不能直接用call_step_store.gas - call_step_store.gas_cost，
                // 所以没有采用在POST_CALL中单独修改gas_left。
                // 因此对于下面的self.gas_left = step.gas - step.gas_cost操作没有放在update_from_next_step中，
                // 因为在执行到PUSH1(4)时，我们需要PUSH1(4)的gas_left = step.gas - step.gas_cost.
                self.gas_left = step.gas;

                res.append(
                    execution_gadgets_map
                        .get(&ExecutionState::POST_CALL_1)
                        .unwrap()
                        .gen_witness(call_trace_step, self),
                );
                res.append(
                    execution_gadgets_map
                        .get(&ExecutionState::POST_CALL_2)
                        .unwrap()
                        .gen_witness(call_trace_step, self),
                );
                prev_is_return_revert_or_stop = false;
                if need_exit_call {
                    prev_step_is_error = false;
                }
            }

            if let Some(next_step) = next_step {
                self.update_from_next_step(next_step);
            }
            let exec_error = self.handle_step_error(step, next_step);
            self.update_call_context(step);

            if exec_error.is_some() {
                prev_step_is_error = true;
            }

            // 根据当前STEP更新MEMORY_CHUNK
            let memory_usage = (step.memory.0.len() / 32) as u64;
            let memory_chunk = self.memory_chunk;
            self.memory_chunk_prev = memory_chunk;

            if memory_usage > memory_chunk {
                self.memory_chunk = memory_usage;
            } else {
                self.memory_chunk = memory_chunk;
            }

            if step.op == OpcodeId::RETURN
                || step.op == OpcodeId::REVERT
                || step.op == OpcodeId::STOP
                || exec_error.is_some()
            {
                // 若为root-call则,下一个状态为end-tx
                if self.parent_call_id[&self.call_id] == 0 {
                    self.next_exec_state = Some(ExecutionState::END_TX)
                } else {
                    self.next_exec_state = Some(ExecutionState::POST_CALL_1);
                }
            }
            // 执行状态后的gas计算下移，不放在update_from_next中，因为在POST_CALL中会改变这个值
            // 这里self.gas_left没有直接赋值为next_step.gas的原因是CALL里STOP时的gas_left应该为cur_gas - cur_gas_cost，而不是next_step.gas
            // 若所报错误为OutOfGas,则gas_left不变,仍然为step.gas, 在相应的错误处理gadget中通过约束prev_gas_left - cur_gas_left = 0来约束
            if let Some(err) = exec_error.clone() {
                match err {
                    ExecError::OutOfGas { .. } => {
                        self.gas_left = step.gas;
                    }
                    _ => self.gas_left = step.gas - step.gas_cost,
                }
            } else {
                self.gas_left = step.gas - step.gas_cost;
            }

            res.append(self.generate_execution_witness(step, &execution_gadgets_map, exec_error));

            match step.op {
                OpcodeId::RETURN | OpcodeId::REVERT | OpcodeId::STOP => {
                    prev_is_return_revert_or_stop = true;
                }
                OpcodeId::CALL | OpcodeId::STATICCALL | OpcodeId::DELEGATECALL => {
                    call_step_store.push(step);
                }
                _ => {}
            }
        }
        let is_last_tx_in_block = tx_idx == geth_data.geth_traces.len();
        // 若为最后一笔交易,则下一个状态是end_block,否则下一个状态为begin_tx_1
        if is_last_tx_in_block {
            self.next_exec_state = Some(ExecutionState::END_BLOCK);
        } else {
            self.next_exec_state = Some(ExecutionState::BEGIN_TX_1);
        }
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::END_TX)
                .unwrap()
                .gen_witness(last_step, self),
        );
        res
    }

    fn generate_execution_witness(
        &mut self,
        trace_step: &GethExecStep,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
        exec_error: Option<ExecError>,
    ) -> Witness {
        let mut res = Witness::default();
        let execution_states = if let Some(exec_error) = exec_error {
            ExecutionState::from_error(trace_step.op, exec_error)
        } else {
            ExecutionState::from_opcode(trace_step.op)
        };
        let execution_states_len = execution_states.len();
        let next_state = self.next_exec_state;
        for (index, execution_state) in execution_states.iter().enumerate() {
            // 遍历opcodeId所生成的execution_state,除第一个和最后一个将在每一个gadget生成witness前设置下一个execution_state
            if index < execution_states_len - 1 {
                self.next_exec_state = Some(execution_states[index + 1]);
            } else {
                self.next_exec_state = next_state;
            }
            if let Some(gadget) = execution_gadgets_map.get(&execution_state) {
                res.append(gadget.gen_witness(trace_step, self));
            } else {
                panic!("execution state {:?} not supported yet", execution_state);
            }
        }
        res
    }

    fn handle_step_error(
        &self,
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> Option<ExecError> {
        if matches!(step.op, OpcodeId::INVALID(_)) {
            return Some(ExecError::InvalidOpcode);
        }

        if let Some(ref error) = step.error {
            let geth_error = GethExecError::from(error.as_str());
            return Some(get_step_reported_error(&step.op, geth_error));
        }

        let cur_call_is_success = self.call_ctx.last().unwrap().is_success;
        let cur_call_is_static = self.call_ctx.last().unwrap().is_static;

        if next_step.is_none() {
            // 1.正常结束的opcode
            if matches!(
                step.op,
                OpcodeId::STOP | OpcodeId::REVERT | OpcodeId::SELFDESTRUCT
            ) {
                return None;
            }
            // 2. 调用合约，op为Return，表示正常返回
            if !self.is_create && step.op == OpcodeId::RETURN {
                return None;
            }
            // 3. 创建合约，call_trace为success且正常Return
            if self.is_create && cur_call_is_success && step.op == OpcodeId::RETURN {
                return None;
            }
        }

        // 默认为0，因为root函数depth == 1
        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        let value = match step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => step.stack.nth_last(2).unwrap(),
            OpcodeId::CREATE | OpcodeId::CREATE2 => step.stack.last().unwrap(),
            _ => Word::zero(),
        };

        if step.depth == next_depth + 1 && !cur_call_is_success {
            if !matches!(step.op, OpcodeId::RETURN) {
                return match step.op {
                    OpcodeId::JUMP | OpcodeId::JUMPI => Some(ExecError::InvalidJump),
                    OpcodeId::RETURNDATACOPY => Some(ExecError::ReturnDataOutOfBounds),
                    OpcodeId::REVERT => None,
                    OpcodeId::SSTORE
                    | OpcodeId::CREATE
                    | OpcodeId::CREATE2
                    | OpcodeId::SELFDESTRUCT
                    | OpcodeId::LOG0
                    | OpcodeId::LOG1
                    | OpcodeId::LOG2
                    | OpcodeId::LOG3
                    | OpcodeId::LOG4
                        if cur_call_is_static =>
                    {
                        Some(ExecError::WriteProtection)
                    }
                    OpcodeId::CALL if cur_call_is_static && !value.is_zero() => {
                        Some(ExecError::WriteProtection)
                    }
                    _ => panic!("call failure without return"),
                };
            } else {
                if self.is_create {
                    let offset = step.stack.last().unwrap();
                    let length = step.stack.nth_last(1).unwrap();
                    if length > Word::from(MAX_CODE_SIZE) {
                        return Some(ExecError::MaxCodeSizeExceeded);
                    } else if length > Word::zero()
                        && !step.memory.is_empty()
                        && step.memory.0.get(offset.low_u64() as usize) == Some(&0xef)
                    {
                        return Some(ExecError::InvalidCreationCode);
                    } else if Word::from(200u64) * length > Word::from(step.gas) {
                        return Some(ExecError::CodeStoreOutOfGas);
                    } else {
                        panic!("failure in RETURN from CREATE, CREATE2");
                    }
                } else {
                    panic!("failure in RETURN")
                }
            }
        }

        if step.depth == next_depth + 1
            && cur_call_is_success
            && !matches!(
                step.op,
                OpcodeId::RETURN | OpcodeId::STOP | OpcodeId::SELFDESTRUCT
            )
        {
            panic!("success result without RETURN, STOP, SELFDESTRUCT")
        }

        let next_pc = next_step.map(|s| s.pc).unwrap_or(1);
        let next_is_success = self
            .call_is_success
            .get(self.call_cnt - self.call_is_success_offset)
            .map_or(true, |v| *v);
        if matches!(
            step.op,
            OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
                | OpcodeId::CREATE
                | OpcodeId::CREATE2
        ) && !next_is_success
            && next_pc != 0
        {
            if step.depth == 1025 {
                return Some(ExecError::Depth(match step.op {
                    OpcodeId::CALL
                    | OpcodeId::CALLCODE
                    | OpcodeId::DELEGATECALL
                    | OpcodeId::STATICCALL => DepthError::Call,
                    OpcodeId::CREATE => DepthError::Create,
                    OpcodeId::CREATE2 => DepthError::Create2,
                    _ => unreachable!("ErrDepth cannot occur in {0}", step.op),
                }));
            }

            // todo 需要实现AccountNotFound，这个需要考虑如何拉取链上账户信息
            // todo InsufficientBalanceError 目前还未实现
            // todo NonceUintOverflow 目前还未实现
            // todo ContractAddressCollision
            // todo Precompile call failures.

            // 在这个逻辑分支里，表示已经出现错误，因为上述指令并没有被执行，所以最后我们需要panic
            panic!("*CALL*/CREATE* code not executed");
        }

        None
    }

    /// 根据opcode更新call_ctx中的变量以及call_is_success_offset
    fn update_call_context(&mut self, step: &GethExecStep) {
        match step.op {
            OpcodeId::CALL
            | OpcodeId::CALLCODE
            | OpcodeId::STATICCALL
            | OpcodeId::DELEGATECALL
            | OpcodeId::CREATE
            | OpcodeId::CREATE2 => {
                // todo 这里检查理论应该满足：
                // 1.对于CALLX: depth < 1025 && (!is_call_or_callcode || caller_balance >= call_value)
                // 2.对于CREATEX: depth < 1025 && caller_balance >= callee_value && caller_nonce < u64::MAX;
                // 因为我们目前还没加入balance，暂时可以先简单过滤其中一种情况，后续可以继续完善
                if step.depth < 1025 {
                    let call = CallInfoContext {
                        is_success: self
                            .call_is_success
                            .get(self.call_cnt - self.call_is_success_offset)
                            .unwrap()
                            .clone(),
                        is_static: step.op == OpcodeId::STATICCALL
                            || self.call_ctx.last().unwrap().is_static,
                    };
                    self.call_ctx.push(call);
                } else {
                    self.call_is_success_offset += 1
                }
                self.call_cnt += 1;
            }
            OpcodeId::RETURN | OpcodeId::REVERT | OpcodeId::STOP => {
                self.call_ctx.pop().unwrap();
            }
            _ => {}
        }
    }

    pub fn get_core_row_without_versatile(
        &self,
        trace_step: &GethExecStep,
        multi_row_cnt: usize,
    ) -> core::Row {
        core::Row {
            block_idx: self.block_idx.into(),
            tx_idx: self.tx_idx.into(),
            tx_is_create: (self.is_create as u8).into(),
            call_id: self.call_id.into(),
            code_addr: self.code_addr,
            pc: trace_step.pc.into(),
            opcode: trace_step.op,
            cnt: multi_row_cnt.into(),
            ..Default::default()
        }
    }

    pub fn get_pop_stack_row_value(&mut self, trace_step: &GethExecStep) -> (state::Row, U256) {
        let value = *trace_step
            .stack
            .0
            .get(self.stack_pointer - 1)
            .expect("error in current_state.get_pop_stack_row");
        let res = state::Row {
            tag: Some(Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(self.stack_pointer.into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        self.stack_pointer -= 1;
        (res, value)
    }

    pub fn get_peek_stack_row_value(
        &mut self,
        trace_step: &GethExecStep,
        index_start_at_1: usize,
    ) -> (state::Row, U256) {
        let value = trace_step
            .stack
            .0
            .get(trace_step.stack.0.len() - index_start_at_1)
            .expect("error in current_state.get_peek_stack_row_value");
        let res = state::Row {
            tag: Some(Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer + 1 - index_start_at_1).into()), // stack pointer start at 1, hence +1
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, *value)
    }

    pub fn get_memory_read_row(&mut self, trace_step: &GethExecStep, offset: U256) -> state::Row {
        // we don't need to consider whether offset.as_usize() panics, which is guaranteed by its callers.
        let value = trace_step
            .memory
            .0
            .get(offset.as_usize())
            .cloned()
            .unwrap_or_default();
        let res = state::Row {
            tag: Some(Tag::Memory),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_memory_write_row(&mut self, offset: U256, value: u8) -> state::Row {
        let res = state::Row {
            tag: Some(Tag::Memory),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_return_data_read_row(&mut self, offset: U256, call_id: u64) -> (state::Row, u8) {
        // we don't need to consider whether offset.as_usize() panics, which is guaranteed by its callers.
        let value = self
            .return_data
            .get(&call_id)
            .unwrap()
            .get(offset.as_usize())
            .cloned()
            .unwrap_or_default();
        let res = state::Row {
            tag: Some(state::Tag::ReturnData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_return_data_write_row(&mut self, offset: U256, value: u8) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::ReturnData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_tstorage_row(
        &mut self,
        key: U256,
        value: U256,
        tstorage_block_tx_idx: U256,
        is_write: bool,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(Tag::TStorage),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some(value >> 128),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(tstorage_block_tx_idx),
            pointer_hi: Some(key >> 128),
            pointer_lo: Some(key.low_u128().into()),
            is_write: Some((is_write as u8).into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_storage_read_row_value(
        &mut self,
        trace_step: &GethExecStep,
        key: U256,
        contract_addr: U256,
    ) -> (state::Row, U256) {
        let value = trace_step.storage.0.get(&key).cloned().unwrap_or_default();
        let res = state::Row {
            tag: Some(Tag::Storage),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some(value >> 128),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(key >> 128),
            pointer_lo: Some(key.low_u128().into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_call_context_read_row(&mut self, op: OpcodeId) -> (state::Row, U256) {
        let (value, tag) = match op {
            OpcodeId::CALLDATASIZE => (
                self.call_data
                    .get(&self.call_id)
                    .unwrap()
                    .len()
                    .clone()
                    .into(),
                CallContextTag::CallDataSize,
            ),
            OpcodeId::CALLER => (
                self.sender.get(&self.call_id).unwrap().clone(),
                CallContextTag::SenderAddr,
            ),
            OpcodeId::CALLVALUE => (
                self.value.get(&self.call_id).unwrap().clone(),
                CallContextTag::Value,
            ),
            OpcodeId::ADDRESS => (
                self.storage_contract_addr
                    .get(&self.call_id)
                    .unwrap()
                    .clone(),
                CallContextTag::StorageContractAddr,
            ),
            _ => {
                panic!("not CALLDATASIZE, CALLER, CALLVALUE or ADDRESS")
            }
        };

        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((tag as usize).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_call_context_read_row_with_arbitrary_tag(
        &mut self,
        tag: state::CallContextTag,
        value: U256,
        call_id: u64,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((tag as usize).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_call_context_write_row(
        &mut self,
        tag: state::CallContextTag,
        value: U256,
        call_id: u64,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((tag as usize).into()),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_storage_write_row(
        &mut self,
        key: U256,
        value: U256,
        contract_addr: U256,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::Storage),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some(value >> 128),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(key >> 128),
            pointer_lo: Some(key.low_u128().into()),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_addr_access_list_read_row(&mut self, contract_addr: U256) -> (state::Row, bool) {
        let is_warm = self.state_db.address_in_access_list(&contract_addr);

        let res = state::Row {
            tag: Some(Tag::AddrInAccessListStorage),
            stamp: Some(self.state_stamp.into()),
            pointer_hi: Some(contract_addr >> 128),
            pointer_lo: Some(contract_addr.low_u128().into()),
            value_hi: None,
            value_lo: Some((is_warm.clone() as u8).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;

        (res, is_warm)
    }
    pub fn get_slot_access_list_read_row(
        &mut self,
        contract_addr: U256,
        storage_key: U256,
    ) -> (state::Row, bool) {
        let is_warm = self
            .state_db
            .slot_in_access_list(&contract_addr, &storage_key);

        let res = state::Row {
            tag: Some(Tag::SlotInAccessListStorage),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some((is_warm.clone() as u8).into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(storage_key >> 128),
            pointer_lo: Some(storage_key.low_u128().into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;

        (res, is_warm)
    }

    pub fn get_addr_access_list_write_row(
        &mut self,
        contract_addr: U256,
        value: bool,
        value_pre: bool,
    ) -> state::Row {
        // 在read完以后这个值实际上已经变为了true
        self.state_db.insert_access_list(contract_addr);

        let res = state::Row {
            tag: Some(Tag::AddrInAccessListStorage),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some((value as u8).into()),
            pointer_hi: Some(contract_addr >> 128),
            pointer_lo: Some(contract_addr.low_u128().into()),
            is_write: Some(1.into()),
            value_pre_hi: None,
            value_pre_lo: Some((value_pre as u8).into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }
    pub fn get_slot_access_list_write_row(
        &mut self,
        contract_addr: U256,
        storage_key: U256,
        value: bool,
        value_pre: bool,
    ) -> state::Row {
        // 在read完以后这个值实际上已经变为了true
        self.state_db
            .insert_slot_access_list(contract_addr, storage_key);

        let res = state::Row {
            tag: Some(Tag::SlotInAccessListStorage),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some((value as u8).into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(storage_key >> 128),
            pointer_lo: Some(storage_key.low_u128().into()),
            is_write: Some(1.into()),
            value_pre_hi: None,
            value_pre_lo: Some((value_pre as u8).into()),
            committed_value_hi: None,
            committed_value_lo: None,
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_storage_full_write_row(
        &mut self,
        key: U256,
        value: U256,
        contract_addr: U256,
        value_pre: U256,
        committed_value: U256,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(Tag::Storage),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some(value >> 128),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(key >> 128),
            pointer_lo: Some(key.low_u128().into()),
            is_write: Some(1.into()),
            value_pre_hi: Some(value_pre >> 128),
            value_pre_lo: Some(value_pre.low_u128().into()),
            committed_value_hi: Some(committed_value >> 128),
            committed_value_lo: Some(committed_value.low_u128().into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_push_stack_row(&mut self, trace: &GethExecStep, value: U256) -> state::Row {
        assert!(
            trace.stack.0.len() <= 1024 - 1,
            "error in current_state.get_push_stack_row_value"
        );
        let res = state::Row {
            tag: Some(Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer + 1).into()),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        self.stack_pointer += 1;
        res
    }

    pub fn get_overwrite_stack_row(
        &mut self,
        _trace_step: &GethExecStep,
        index_start_at_1: usize,
        value: U256,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer - index_start_at_1 + 1).into()), // stack pointer start at 1, hence +1
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }
    // get_code_copy_rows
    // @input
    //  address: code address
    //  src_offset: copy from where
    //  dst_offset: copy to where (in memory)
    //  copy_length: copy length
    // @return
    //  copy rows contains real copy rows and padding rows
    //  state rows contains memory rows
    //  arithmetic length rows contains rows of src_offset + copy_length - code_length
    //  arithmetic u64overflow rows contains rows of u64overflow of src_offset
    //  public rows contains code size
    //  real copy length
    //  padding length
    pub fn get_code_copy_rows<F: Field>(
        &mut self,
        address: U256,
        src_offset: U256,
        dst_offset: U256,
        copy_length: U256,
        is_extcodecopy: bool,
    ) -> (
        Vec<copy::Row>,
        Vec<state::Row>,
        Vec<arithmetic::Row>,
        Vec<arithmetic::Row>,
        public::Row,
        u64,
        u64,
        U256,
    ) {
        let dst_offset = dst_offset.low_u64();
        // src offset check
        // if src offset is greater than u64::max, then set src offset is max code size,
        // for code size can not succeed code size
        let (arith_src_overflow_rows, arith_src_overflow_values) =
            operation::u64overflow::gen_witness::<F>(vec![src_offset]);
        let src_offset = if arith_src_overflow_values[0].is_zero() {
            src_offset
        } else {
            MAX_CODESIZE.into()
        };

        // get code length
        let code = self.bytecode.get(&address);
        let (code_size, addr_exists) = if code.is_none() && is_extcodecopy {
            (U256::zero(), U256::zero())
        } else {
            (U256::from(code.unwrap().code.len()), U256::one())
        };
        let public_code_size_row = self.get_public_code_info_row(public::Tag::CodeSize, address);

        // calc real_length and zero_length
        // arith_results: [overflow,real_length,zero_length]
        let (arith_length_rows, arith_results) =
            operation::length::gen_witness::<F>(vec![src_offset, copy_length, code_size]);
        let real_length = arith_results[1];
        let zero_length = arith_results[2];

        // way of processing address and src and len, reference go-ethereum's method
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go#L373
        let real_length = real_length.low_u64();
        let zero_length = zero_length.low_u64();

        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let codecopy_stamp = self.state_stamp;
        if real_length > 0 {
            let mut acc_pre = U256::from(0);
            let temp_256_f = F::from(256);
            for i in 0..real_length {
                let code = self.bytecode.get(&address).unwrap();
                let byte = code.get(src_offset.as_usize() + i as usize).unwrap().value;

                // calc acc
                let acc: U256 = if i == 0 {
                    byte.into()
                } else {
                    let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                    let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                    acc_f = byte_f + acc_f * temp_256_f;
                    convert_f_to_u256(&acc_f)
                };
                acc_pre = acc;

                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Bytecode,
                    src_id: address,
                    src_pointer: src_offset.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Memory,
                    dst_id: self.call_id.into(),
                    dst_pointer: dst_offset.into(),
                    dst_stamp: codecopy_stamp.into(),
                    cnt: i.into(),
                    len: real_length.into(),
                    acc,
                });
                // it's guaranteed by Ethereum that dst + i doesn't overflow, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L31
                state_rows.push(self.get_memory_write_row(U256::from(dst_offset + i), byte));
            }
        }

        let codecopy_padding_stamp = self.state_stamp;
        if zero_length > 0 {
            for i in 0..zero_length {
                state_rows.push(self.get_memory_write_row(
                    // in the same way, dst + code_copy_length + i doesn't overflow
                    U256::from(dst_offset + real_length + i),
                    0u8,
                ));
                copy_rows.push(copy::Row {
                    byte: 0.into(),
                    src_type: copy::Tag::Zero,
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Memory,
                    dst_id: self.call_id.into(),
                    dst_pointer: (dst_offset + real_length).into(),
                    dst_stamp: codecopy_padding_stamp.into(),
                    cnt: i.into(),
                    len: U256::from(zero_length),
                    acc: 0.into(),
                })
            }
        }

        (
            copy_rows,
            state_rows,
            arith_length_rows,
            arith_src_overflow_rows,
            public_code_size_row,
            real_length,
            zero_length,
            addr_exists,
        )
    }

    pub fn get_mcopy_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        dest_offset: U256,
        offset: U256,
        length: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let dest_offset = dest_offset.low_u64();
        let offset = offset.low_u64();
        let length = length.low_u64();

        let (mut copy_rows, mut state_rows) = (vec![], vec![]);

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);
        let stamp = self.state_stamp;

        // get memory copy rows and state read rows
        for i in 0..length {
            let byte = trace
                .memory
                .0
                .get((offset + i) as usize)
                .cloned()
                .unwrap_or_default();

            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Memory,
                src_id: self.call_id.into(),
                src_pointer: offset.into(),
                src_stamp: stamp.into(),
                dst_type: copy::Tag::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: dest_offset.into(),
                dst_stamp: (stamp + length).into(), // writing to memory happens after reading from memory
                cnt: i.into(),
                len: U256::from(length),
                acc,
            });
            state_rows.push(self.get_memory_read_row(trace, U256::from(offset + i)));
        }

        // get state write rows
        for i in 0..length {
            let byte = trace
                .memory
                .0
                .get((offset + i) as usize)
                .cloned()
                .unwrap_or_default();
            state_rows.push(self.get_memory_write_row(U256::from(dest_offset + i), byte));
        }

        (copy_rows, state_rows)
    }

    pub fn get_call_return_data_copy_rows<F: Field>(
        &mut self,
        dst: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>, u64) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        // it's guaranteed by caller that it is in range u64
        let dst_offset = dst.low_u64();
        let length = len.low_u64();
        let copy_stamp = self.state_stamp;
        let return_data_length = self
            .return_data
            .get(&self.returndata_call_id)
            .unwrap()
            .len() as u64;
        // way of processing len, reference go-ethereum's method
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go#L664
        let copy_length = if length > return_data_length {
            return_data_length
        } else {
            length
        };

        if copy_length > 0 {
            let mut acc_pre = U256::from(0);
            let temp_256_f = F::from(256);
            for i in 0..copy_length {
                let return_data = self.return_data.get(&self.returndata_call_id).unwrap();
                let byte = return_data.get(i as usize).cloned().unwrap_or_default();

                // calc acc
                let acc: U256 = if i == 0 {
                    byte.into()
                } else {
                    let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                    let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                    acc_f = byte_f + acc_f * temp_256_f;
                    convert_f_to_u256(&acc_f)
                };
                acc_pre = acc;

                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Returndata,
                    src_id: self.returndata_call_id.into(),
                    src_pointer: 0.into(),
                    src_stamp: copy_stamp.into(),
                    dst_type: copy::Tag::Memory,
                    dst_id: self.call_id.into(),
                    dst_pointer: dst_offset.into(),
                    dst_stamp: (copy_stamp + copy_length).into(),
                    cnt: i.into(),
                    len: copy_length.into(),
                    acc,
                });
                state_rows.push(
                    self.get_return_data_read_row(i.into(), self.returndata_call_id)
                        .0,
                );
            }

            for i in 0..copy_length {
                let return_data = self.return_data.get(&self.returndata_call_id).unwrap();
                let byte = return_data.get(i as usize).cloned().unwrap_or_default();
                // it's guaranteed by Ethereum that dst + i doesn't overflow, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L67
                state_rows.push(self.get_memory_write_row(dst + i, byte));
            }
        }

        (copy_rows, state_rows, copy_length)
    }

    pub fn get_return_data_copy_rows<F: Field>(
        &mut self,
        dst: U256,
        src: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        // it's guaranteed by caller that it is in range u64
        let src_offset = src.low_u64();
        let _dst_offset = dst.low_u64();
        let length = len.low_u64();

        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        let dst_copy_stamp = self.state_stamp + length;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..length {
            // todo situations to deal: if according to address ,get nil
            let data = self
                .return_data
                .get(&self.returndata_call_id)
                .expect("return data doesn't exist at current call_id");
            let byte = data
                .get((src_offset + i) as usize)
                .cloned()
                .expect("err return data out of bounds. should not occur here.");

            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Returndata,
                src_id: self.returndata_call_id.into(),
                src_pointer: src,
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: dst,
                dst_stamp: dst_copy_stamp.into(),
                cnt: i.into(),
                len: len.into(),
                acc,
            });
            // it's guaranteed by Ethereum that src + i < returndata's total length, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go#L337
            state_rows.push(
                self.get_return_data_read_row(src + i, self.returndata_call_id)
                    .0,
            );
        }

        for i in 0..length {
            let data = self
                .return_data
                .get(&self.returndata_call_id)
                .expect("return data doesn't exist at current call_id");
            let byte = data
                .get((src + i).as_usize())
                .cloned()
                .expect("err return data out of bounds. should not occur here.");
            // it's guaranteed by Ethereum that dst + i doesn't overflow, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L27
            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }

        (copy_rows, state_rows)
    }
    pub fn get_calldata_read_row(&mut self, offset: U256) -> (state::Row, u8) {
        // we don't need to consider whether offset.as_usize() panics, which is guaranteed by its callers.
        let val = self.call_data[&self.call_id]
            .get(offset.as_usize())
            .cloned()
            .unwrap_or_default();
        let state_row = state::Row {
            tag: Some(state::Tag::CallData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(val.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (state_row, val)
    }

    pub fn get_calldata_write_row(
        &mut self,
        offset: U256,
        value: u8,
        dst_call_id: u64,
    ) -> state::Row {
        let state_row = state::Row {
            tag: Some(Tag::CallData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(dst_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(offset),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        state_row
    }

    pub fn get_calldata_copy_rows<F: Field>(
        //TODO: in its caller (calldatacopy.rs), guarantee that src and len are the result of length arithmetic.
        &mut self,
        dst: U256,
        src: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        // it's guaranteed by caller that it is in range u64
        let length = len.low_u64();

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..length {
            // we don't need to consider overflow panics, which is guaranteed by its callers.
            let (state_row, byte) = self.get_calldata_read_row(src + i);

            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Calldata,
                src_id: self.call_id.into(),
                src_pointer: src,
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: dst,
                dst_stamp: (copy_stamp + length).into(),
                cnt: i.into(),
                len: len.into(),
                acc,
            });
            state_rows.push(state_row);
        }

        for i in 0..length {
            let call_data = self.call_data.get(&self.call_id).unwrap();
            // it's guaranteed by the caller that (src + i).as_usize() doesn't panic.
            let byte = call_data
                .get((src + i).as_usize())
                .cloned()
                .unwrap_or_default();
            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }

        (copy_rows, state_rows)
    }

    pub fn get_calldata_write_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        src: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        // it's guaranteed by caller that it is in range u64
        let args_offset = src.low_u64();
        let args_len = len.low_u64();

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        let mut calldata_new = vec![];

        for i in 0..args_len {
            let byte = trace
                .memory
                .0
                .get((args_offset + i) as usize)
                .cloned()
                .unwrap_or_default();
            calldata_new.push(byte);
            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Memory,
                src_id: self.call_id.into(),
                src_pointer: args_offset.into(),
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Calldata,
                dst_id: self.call_id_new.into(),
                dst_pointer: 0.into(),
                dst_stamp: (copy_stamp + args_len).into(),
                cnt: i.into(),
                len: args_len.into(),
                acc,
            });
            // it's guaranteed by Ethereum that src + i doesn't overflow,
            // reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L67
            state_rows.push(self.get_memory_read_row(trace, src + i));
        }

        for i in 0..args_len as usize {
            state_rows.push(self.get_calldata_write_row(
                i.into(),
                calldata_new[i],
                self.call_id_new,
            ));
        }

        self.call_data.insert(self.call_id_new, calldata_new);

        (copy_rows, state_rows)
    }

    /// 从calldata的offset位置读取32byte数据至stack of evm.
    pub fn get_calldata_load_rows<F: Field>(
        &mut self,
        offset: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let call_data = &self.call_data[&self.call_id];

        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        // offset 可能溢出u64或者小于u64但offset+32>=len of calldata
        let mut offset_start = offset;

        // 系数，乘以256标识将一个值左移8bit，
        let temp_256_f = F::from(256);
        // calldataload 读取32byte数据
        for _i in 0..2 {
            let mut acc_pre = U256::from(0);
            let stamp_start = self.state_stamp;
            for j in 0..16 {
                // offset 可能大于u64::max-32，导致offset_start.as_usize()+j>u64::max使程序panic
                let byte = if offset_start + j <= (u64::MAX - 32).into() {
                    call_data
                        .get(offset_start.as_usize() + j as usize)
                        .cloned()
                        .unwrap_or_default()
                } else {
                    // 溢出时，返回0值作为读取的数据，与EVM规范保持一致
                    0
                };

                // 由于数据是一个个字节读取，acc标识累计读取的数据，所以acc_f*temp_256_f+byte
                // 标识最新读取的完整字符串内容：即将前面累计读取的内容左移8bit(1个字节)再加上新读取的字节
                // 示例：完整字符串 0x123456
                // 读取0x12 --> acc_pre=0x12 --> acc=0x12
                // 读取0x34 --> acc_f=0x1234 --> acc=0x1234
                // 读取0x56 --> acc_f=0x123456 --> acc=0x123456
                let acc: U256 = if j == 0 {
                    byte.into()
                } else {
                    let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                    let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                    acc_f = byte_f + acc_f * temp_256_f;
                    convert_f_to_u256(&acc_f)
                };
                acc_pre = acc;
                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Calldata,
                    src_id: self.call_id.into(),
                    src_pointer: offset_start,
                    src_stamp: stamp_start.into(),
                    dst_type: copy::Tag::Null,
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: j.into(),
                    len: 16.into(),
                    acc,
                });
                state_rows.push(state::Row {
                    tag: Some(state::Tag::CallData),
                    stamp: Some((stamp_start + j as u64).into()),
                    value_hi: None,
                    value_lo: Some(byte.into()),
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    pointer_lo: Some(offset_start + j),
                    is_write: Some(0.into()),
                    ..Default::default()
                });
                self.state_stamp += 1;
            }
            // 每次循环读取16byte数据
            offset_start = offset_start + 16;
        }
        (copy_rows, state_rows)
    }

    /// Load calldata from public table to state table
    pub fn get_load_calldata_copy_rows<F: Field>(&mut self) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let calldata = &self.call_data[&self.call_id];
        let len = calldata.len();
        let stamp_start = self.state_stamp;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for (i, &byte) in calldata.iter().enumerate() {
            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            if self.is_create {
                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Bytecode,
                    src_id: self.code_addr,
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Calldata,
                    dst_id: self.call_id.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: stamp_start.into(),
                    cnt: i.into(),
                    len: len.into(),
                    acc,
                });
            } else {
                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::PublicCalldata,
                    src_id: self.get_block_tx_idx().into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Calldata,
                    dst_id: self.call_id.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: stamp_start.into(),
                    cnt: i.into(),
                    len: len.into(),
                    acc,
                });
            }

            state_rows.push(state::Row {
                tag: Some(state::Tag::CallData),
                stamp: Some(self.state_stamp.into()),
                value_hi: None,
                value_lo: Some(byte.into()),
                call_id_contract_addr: Some(self.call_id.into()),
                pointer_hi: None,
                pointer_lo: Some(i.into()),
                is_write: Some(1.into()),
                ..Default::default()
            });
            self.state_stamp += 1;
        }
        (copy_rows, state_rows)
    }

    ///load 32-bytes value from memory
    pub fn get_mload_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let mut stamp_start = self.state_stamp;
        let mut offset_start = offset;

        let temp_256_f = F::from(256);

        for _i in 0..2 {
            let mut acc_pre = U256::from(0);
            for j in 0..16 {
                // we don't need to consider whether (offset_start + j).as_usize() panics because Ethereum has checked whether it overflows.
                // reference : https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L39
                let byte = trace
                    .memory
                    .0
                    .get((offset_start + j).as_usize())
                    .cloned()
                    .unwrap_or_default();

                // calc acc
                let acc: U256 = if j == 0 {
                    byte.into()
                } else {
                    let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                    let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                    acc_f = byte_f + acc_f * temp_256_f;
                    convert_f_to_u256(&acc_f)
                };
                acc_pre = acc;

                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Memory,
                    src_id: self.call_id.into(),
                    src_pointer: offset_start,
                    src_stamp: stamp_start.into(),
                    dst_type: copy::Tag::Null,
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: j.into(),
                    len: 16.into(),
                    acc,
                });
                state_rows.push(state::Row {
                    tag: Some(Tag::Memory),
                    stamp: Some((stamp_start + j as u64).into()),
                    value_hi: None,
                    value_lo: Some(byte.into()),
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    // it's guaranteed by Ethereum that offset_start + j doesn't overflow.
                    pointer_lo: Some(offset_start + j),
                    is_write: Some(0.into()),
                    ..Default::default()
                });
                self.state_stamp += 1;
            }
            stamp_start += 16;
            offset_start += 16.into();
        }

        (copy_rows, state_rows)
    }

    //store 32-bytes value to memory
    pub fn get_mstore_rows<F: Field>(
        &mut self,
        offset: U256,
        value: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let mut stamp_start = self.state_stamp;
        let mut offset_start = offset;

        let temp_256_f = F::from(256);

        for i in 0..2 {
            let mut acc_pre = U256::from(0);
            for j in 0..16 {
                let byte = value.byte(31 - (i * 16 + j));

                // calc acc
                let acc: U256 = if j == 0 {
                    byte.into()
                } else {
                    let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                    let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                    acc_f = byte_f + acc_f * temp_256_f;
                    convert_f_to_u256(&acc_f)
                };
                acc_pre = acc;

                copy_rows.push(copy::Row {
                    byte: byte.into(),
                    src_type: copy::Tag::Null,
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Memory,
                    dst_id: self.call_id.into(),
                    dst_pointer: offset_start,
                    dst_stamp: stamp_start.into(),
                    cnt: j.into(),
                    len: 16.into(),
                    acc,
                });
                state_rows.push(state::Row {
                    tag: Some(state::Tag::Memory),
                    stamp: Some((stamp_start + j as u64).into()),
                    value_hi: None,
                    value_lo: Some(byte.into()),
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    // it's guaranteed by Ethereum that offset_start + j doesn't overflow, reference : https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L47
                    pointer_lo: Some(offset_start + j),
                    is_write: Some(1.into()),
                    ..Default::default()
                });
                self.state_stamp += 1;
            }
            stamp_start += 16;
            offset_start += 16.into();
        }

        (copy_rows, state_rows)
    }

    /// Load calldata from public table to state table
    pub fn get_write_call_context_row(
        &mut self,
        value_hi: Option<U256>,
        value_lo: Option<U256>,
        context_tag: state::CallContextTag,
        call_id: Option<U256>,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi,
            value_lo,
            call_id_contract_addr: match call_id {
                Some(call_id) => Some(call_id),
                None => Some(self.call_id.into()),
            },
            pointer_hi: None,
            pointer_lo: Some((context_tag as u8).into()),
            is_write: Some(1.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_return_revert_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        // it's guaranteed by caller that it is in range u64
        let length = len.low_u64();
        let copy_stamp = self.state_stamp;
        let dst_copy_stamp = self.state_stamp + length;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..length {
            // we don't need to consider whether (offset + i).as_usize() panics because Ethereum has checked whether it overflows.
            // reference : https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L111
            let byte = trace
                .memory
                .0
                .get((offset + i).as_usize())
                .cloned()
                .unwrap_or_default();

            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Memory,
                src_id: self.call_id.into(),
                src_pointer: offset,
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Returndata,
                dst_id: self.call_id.into(),
                dst_pointer: 0.into(),
                dst_stamp: dst_copy_stamp.into(),
                cnt: i.into(),
                len,
                acc,
            });
            // it's guaranteed by Ethereum that offset + i doesn't overflow
            state_rows.push(self.get_memory_read_row(trace, offset + i));
        }
        for i in 0..length {
            let byte = trace
                .memory
                .0
                .get((offset + i).as_usize())
                .cloned()
                .unwrap_or_default();
            state_rows.push(self.get_return_data_write_row(i.into(), byte));
        }

        (copy_rows, state_rows)
    }
    pub fn get_returndata_call_id_row(&mut self, is_write: bool) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: None,
            value_lo: Some(self.returndata_call_id.into()),
            call_id_contract_addr: None,
            pointer_hi: None,
            pointer_lo: Some((state::CallContextTag::ReturnDataCallId as u8).into()),
            is_write: Some((is_write as u8).into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        res
    }
    pub fn get_returndata_size_row(&mut self) -> (state::Row, U256) {
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((self.returndata_size >> 128).as_u128().into()),
            value_lo: Some(self.returndata_size.low_u128().into()),
            call_id_contract_addr: Some(self.returndata_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((CallContextTag::ReturnDataSize as u8).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, self.returndata_size.into())
    }
    pub fn get_current_returndata_size_read_row(&mut self) -> (state::Row, U256) {
        let returndata_size: U256 = self
            .return_data
            .get(&self.returndata_call_id)
            .map(|v| v.len())
            .unwrap_or_default()
            .into();
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((returndata_size >> 128).as_u128().into()),
            value_lo: Some(returndata_size.low_u128().into()),
            call_id_contract_addr: Some(self.returndata_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((CallContextTag::ReturnDataSize as u8).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, returndata_size)
    }
    pub fn get_storage_contract_addr_row(&mut self) -> (state::Row, U256) {
        let value = self.storage_contract_addr.get(&self.call_id).unwrap();
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value.clone() >> 128).as_u128().into()),
            value_lo: Some(value.clone().low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((CallContextTag::StorageContractAddr as u8).into()),
            is_write: Some(0.into()),
            ..Default::default()
        };
        self.state_stamp += 1;
        (res, value.clone())
    }

    pub fn get_log_bytes_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let length = len.low_u64();
        let copy_stamp = self.state_stamp;
        let log_stamp = self.log_stamp;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..length {
            // we don't need to consider whether (offset + i).as_usize() panics because Ethereum has checked whether it overflows.
            // reference : https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L119
            let byte = trace
                .memory
                .0
                .get((offset + i).as_usize())
                .cloned()
                .unwrap_or_default();

            // calc acc
            let acc: U256 = if i == 0 {
                byte.into()
            } else {
                let mut acc_f = convert_u256_to_f::<F>(&acc_pre);
                let byte_f = convert_u256_to_f::<F>(&U256::from(byte));
                acc_f = byte_f + acc_f * temp_256_f;
                convert_f_to_u256(&acc_f)
            };
            acc_pre = acc;
            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::Memory,
                src_id: self.call_id.into(),
                src_pointer: offset,
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::PublicLog,
                dst_id: self.get_block_tx_idx().into(),
                dst_pointer: 0.into(),
                dst_stamp: log_stamp.into(), // PublicLog index
                cnt: i.into(),
                len: len.into(),
                acc,
            });
            // it's guaranteed by Ethereum that offset + i doesn't overflow.
            state_rows.push(self.get_memory_read_row(trace, offset + i));
        }

        (copy_rows, state_rows)
    }

    // core_row_1.vers_26 ~ vers31
    pub fn get_public_log_data_size_row(&self, data_len: U256) -> public::Row {
        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), "block_tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(format!("vers_{}", 29), format!("log tag={}", "DataSize"));
        comments.insert(format!("vers_{}", 30), "0".into());
        comments.insert(format!("vers_{}", 31), "data_len".into());

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            block_tx_idx: Some(U256::from(self.get_block_tx_idx())),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(LogTag::DataSize as u64)),
            value_2: Some(0.into()),
            value_3: Some(data_len),
            comments,
            ..Default::default()
        };
        public_row
    }

    pub fn get_public_log_topic_row(
        &self,
        opcode_id: OpcodeId,
        topic_hash_hi: Option<U256>,
        topic_hash_lo: Option<U256>,
    ) -> public::Row {
        let topic_log_tag = opcode_id.as_u8() - (OpcodeId::LOG1).as_u8() - (self.topic_left as u8)
            + (LogTag::Topic0 as u8);

        let topic_tag = match topic_log_tag {
            5 => "Topic0",
            6 => "Topic1",
            7 => "Topic2",
            8 => "Topic3",
            _ => panic!(),
        };

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), "block_tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(
            format!("vers_{}", 29),
            format!("topic_log_tag={}", topic_tag),
        );
        comments.insert(format!("vers_{}", 30), "topic_hash[..16]".into());
        comments.insert(format!("vers_{}", 31), "topic_hash[16..]".into());

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            block_tx_idx: Some(U256::from(self.get_block_tx_idx())),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(topic_log_tag as u64)),
            value_2: topic_hash_hi, // topic_hash[..16]
            value_3: topic_hash_lo, // topic_hash[16..]
            comments,
            ..Default::default()
        };

        public_row
    }

    pub fn get_public_log_topic_num_addr_row(&self, opcode_id: OpcodeId) -> public::Row {
        let log_tag: LogTag;
        let log_tag_name: &str;

        match opcode_id {
            OpcodeId::LOG0 => {
                log_tag = LogTag::AddrWith0Topic;
                log_tag_name = "AddrWith0Topic"
            }
            OpcodeId::LOG1 => {
                log_tag = LogTag::AddrWith1Topic;
                log_tag_name = "AddrWith1Topic"
            }
            OpcodeId::LOG2 => {
                log_tag = LogTag::AddrWith2Topic;
                log_tag_name = "AddrWith2Topic"
            }
            OpcodeId::LOG3 => {
                log_tag = LogTag::AddrWith3Topic;
                log_tag_name = "AddrWith3Topic"
            }
            OpcodeId::LOG4 => {
                log_tag = LogTag::AddrWith4Topic;
                log_tag_name = "AddrWith4Topic"
            }
            _ => panic!(),
        };

        // tx_log	tx_idx	log_stamp=0	log_tag=addrWithXLog	0x0	0x0

        // get contract addr
        let contract_addr = *self.storage_contract_addr.get(&self.call_id).unwrap();
        let value_hi = (contract_addr >> 128).as_u128();
        let value_lo = contract_addr.low_u128();

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), "block_tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(format!("vers_{}", 29), format!("log_tag={}", log_tag_name));
        comments.insert(format!("vers_{}", 30), "address[..4]".into());
        comments.insert(format!("vers_{}", 31), "address[4..]".into());

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            block_tx_idx: Some(U256::from(self.get_block_tx_idx())),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(log_tag as u64)),
            value_2: Some(U256::from(value_hi)),
            value_3: Some(U256::from(value_lo)),
            comments,
            ..Default::default()
        };
        public_row
    }

    pub fn get_public_tx_row(&self, tag: public::Tag, index: usize) -> public::Row {
        let start_idx = PUBLIC_COLUMN_START_IDX - index * PUBLIC_COLUMN_WIDTH;
        let values: [Option<U256>; PUBLIC_NUM_VALUES];
        let value_comments: [String; PUBLIC_NUM_VALUES];
        let mut block_tx_idx = self.get_block_tx_idx();

        match tag {
            public::Tag::TxToCallDataSize => {
                values = [
                    Some(self.code_addr >> 128),
                    Some(self.code_addr.low_u128().into()),
                    None,
                    Some(self.call_data_size[&self.call_id].into()),
                ];
                value_comments = [
                    "to_hi".into(),
                    "to_lo".into(),
                    "0".into(),
                    "tx.input.len".into(),
                ];
            }
            public::Tag::TxFromValue => {
                values = [
                    Some(self.sender[&self.call_id] >> 128),
                    Some(self.sender[&self.call_id].low_u128().into()),
                    Some(self.value[&self.call_id] >> 128),
                    Some(self.value[&self.call_id].low_u128().into()),
                ];
                value_comments = [
                    "from[..16]".into(),
                    "from[16..]".into(),
                    "tx_value[..16]".into(),
                    "tx_value[16..]".into(),
                ]
            }
            public::Tag::BlockTxLogNumAndPrevrandao => {
                values = [
                    Some(
                        self.tx_num_in_block
                            .get(&self.block_idx)
                            .unwrap()
                            .to_owned()
                            .into(),
                    ),
                    Some(
                        self.log_num_in_block
                            .get(&self.block_idx)
                            .unwrap()
                            .to_owned()
                            .into(),
                    ),
                    Some(self.prevrandao >> 128),
                    Some(self.prevrandao.low_u128().into()),
                ];
                value_comments = [
                    "tx_num_in_block".into(),
                    "log_num_in_block".into(),
                    "prevrandao_hi".into(),
                    "prevrandao_lo".into(),
                ];
                block_tx_idx = self.block_idx;
            }

            public::Tag::TxGasLimitAndGasPrice => {
                values = [
                    Some(0.into()),
                    Some(self.tx_gaslimit.into()),
                    Some(self.tx_gasprice >> 128),
                    Some(self.tx_gasprice.low_u128().into()),
                ];
                value_comments = [
                    "0".into(),
                    "gaslimit".into(),
                    "gas price hi".into(),
                    "gas price lo".into(),
                ];
            }

            public::Tag::BlockNumber => {
                values = [
                    None,
                    Some(self.block_number_first_block.into()),
                    None,
                    Some(self.block_num_in_chunk.into()),
                ];
                value_comments = [
                    "".into(),
                    "First Block Number".into(),
                    "".into(),
                    "Block Num in chunk".into(),
                ];
                block_tx_idx = 0;
            }
            public::Tag::TxIsCreateAndStatus => {
                values = [
                    Some((self.is_create as u8).into()),
                    Some(self.call_data_gas_cost().into()),
                    Some(
                        self.call_data_size
                            .get(&self.call_id)
                            .unwrap_or(&U256::zero())
                            .into(),
                    ),
                    Some(0.into()), // tx_status
                ];
                value_comments = [
                    "is_create".into(),
                    "call_data_gas_cost".into(),
                    "call_data_length".into(),
                    "tx_status".into(),
                ];
            }
            public::Tag::BlockCoinbaseAndTimestamp => {
                values = [
                    Some(self.coinbase >> 128),
                    Some(self.coinbase.low_u128().into()),
                    Some(self.timestamp >> 128),
                    Some(self.timestamp.low_u128().into()),
                ];
                value_comments = [
                    "block_coinbase_hi".into(),
                    "block_coinbase_lo".into(),
                    "block_timestamp_hi".into(),
                    "block_timestamp_lo".into(),
                ];
                block_tx_idx = self.block_idx;
            }
            public::Tag::BlockGasLimitAndBaseFee => {
                values = [
                    Some(0.into()),
                    Some(self.block_gaslimit.into()),
                    Some(self.basefee >> 128),
                    Some(self.basefee.low_u128().into()),
                ];
                value_comments = [
                    "0".into(),
                    "block_gaslimit".into(),
                    "basefee_hi".into(),
                    "basefee_lo".into(),
                ];
                block_tx_idx = self.block_idx;
            }
            public::Tag::ChainId => {
                values = [
                    Some(self.chain_id >> 128),
                    Some(self.chain_id.low_u128().into()),
                    None,
                    None,
                ];
                value_comments = [
                    "chain_id_hi".into(),
                    "chain_id_lo".into(),
                    "".into(),
                    "".into(),
                ];
                block_tx_idx = 0;
            }
            _ => panic!(),
        };

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", start_idx), "tag".into());
        comments.insert(format!("vers_{}", start_idx + 1), "block_tx_idx".into());
        comments.insert(format!("vers_{}", start_idx + 2), value_comments[0].clone());
        comments.insert(format!("vers_{}", start_idx + 3), value_comments[1].clone());
        comments.insert(format!("vers_{}", start_idx + 4), value_comments[2].clone());
        comments.insert(format!("vers_{}", start_idx + 5), value_comments[3].clone());

        let public_row = public::Row {
            tag,
            block_tx_idx: Some(U256::from(block_tx_idx as u64)),
            value_0: values[0],
            value_1: values[1],
            value_2: values[2],
            value_3: values[3],
            comments,
            ..Default::default()
        };

        public_row
    }

    // get public row for codehash or codesize by code_addr
    pub fn get_public_code_info_row(&self, tag: public::Tag, code_addr: U256) -> public::Row {
        let bytecode = self
            .bytecode
            .get(&code_addr)
            .and_then(|b| Some(b.code()))
            .unwrap_or(vec![]);

        let (name, value) = match tag {
            public::Tag::CodeSize => ("CodeSize", bytecode.len().into()),
            public::Tag::CodeHash => ("CodeHash", calc_keccak(&bytecode)),
            _ => panic!(),
        };

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", name));
        comments.insert(format!("vers_{}", 27), "none".into());
        comments.insert(format!("vers_{}", 28), "address_hi".into());
        comments.insert(format!("vers_{}", 29), "address_lo".into());
        comments.insert(format!("vers_{}", 30), format!("{}_hi", name));
        comments.insert(format!("vers_{}", 31), format!("{}_lo", name));

        let public_row = public::Row {
            tag,
            value_0: Some(code_addr >> 128),
            value_1: Some(code_addr.low_u128().into()),
            value_2: Some(value >> 128),
            value_3: Some(value.low_u128().into()),
            comments,
            ..Default::default()
        };

        public_row
    }

    /// evm中，get_committed_value取值顺序 pending -> original
    pub fn get_committed_value(&self, address: &Word, key: &Word, tx_idx: usize) -> (bool, U256) {
        match self.state_db.get_pending_storage(address, key, tx_idx) {
            Some(value) => (true, value),
            None => match self.state_db.get_original_storage(address, key) {
                Some(value) => (true, value),
                None => (false, U256::zero()),
            },
        }
    }

    /// evm中，get_dirty_value取值顺序 dirty -> pending -> original
    /// pending中是上一笔交易最后一次sstore写入的值，在get_pending_storage会对tx_idx进行比较
    /// 此处输入的tx_idx为current_state.tx_idx
    pub fn get_dirty_value(&self, address: &Word, key: &Word, tx_idx: usize) -> (bool, U256) {
        match self.state_db.get_dirty_storage(address, key) {
            Some(value) => (true, value),
            None => self.get_committed_value(address, key, tx_idx),
        }
    }

    /// 每次sstore会调用这个函数
    pub fn insert_dirty_storage(&mut self, address: Word, key: U256, value: U256) {
        self.state_db.insert_dirty_storage(address, key, value);
    }
}

pub fn get_and_insert_shl_shr_rows<F: Field>(
    shift: U256,
    value: U256,
    op: OpcodeId,
    core_row_1: &mut core::Row,
    core_row_2: &mut core::Row,
) -> (Vec<arithmetic::Row>, Vec<exp::Row>) {
    // 255 - a
    // the main purpose is to determine whether shift is greater than or equal to 256
    // that is, whether 2<<shift will overflow
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![BIT_SHIFT_MAX_IDX.into(), shift]);

    // mul_div_num = 2<<stack_shift
    let (mul_div_num, exp_rows, exp_arith_mul_rows) = exp::Row::from_operands(U256::from(2), shift);

    // if Opcode is SHL, then result is stack_value * mul_div_num
    // if Opcode is SHR, then result is stack_value / mul_div_num
    let (arithmetic_mul_div_rows, _) = match op {
        OpcodeId::SHL => operation::mul::gen_witness(vec![value, mul_div_num]),
        OpcodeId::SHR => operation::div_mod::gen_witness(vec![value, mul_div_num]),
        _ => panic!("not shl or shr"),
    };

    // insert arithmetic-sub in lookup
    core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
    // insert arithmetic-mul_div in lookup
    core_row_2.insert_arithmetic_lookup(1, &arithmetic_mul_div_rows);

    // insert exp lookup
    core_row_1.insert_exp_lookup(U256::from(2), shift, mul_div_num);

    let mut arithmetic_rows = vec![];
    arithmetic_rows.extend(arithmetic_sub_rows);
    arithmetic_rows.extend(arithmetic_mul_div_rows);
    arithmetic_rows.extend(exp_arith_mul_rows);

    (arithmetic_rows, exp_rows)
}

pub fn get_and_insert_signextend_rows<F: Field>(
    signextend_operands: [U256; 2],
    arithmetic_operands: [U256; 2],
    core_row_0: &mut core::Row,
    _core_row_1: &mut core::Row,
    core_row_2: &mut core::Row,
) -> (Vec<bitwise::Row>, Vec<arithmetic::Row>) {
    // get arithmetic rows
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![arithmetic_operands[0], arithmetic_operands[1]]);
    const START_COL_IDX: usize = 25;

    // calc signextend by bit
    let (signextend_result_vec, bitwise_rows_vec) =
        signextend_by_bit::<F>(signextend_operands[0], signextend_operands[1]);

    // insert bitwise lookup
    for (i, bitwise_lookup) in bitwise_rows_vec.iter().enumerate() {
        core_row_2.insert_bitwise_lookups(i, bitwise_lookup.last().unwrap());
    }
    // insert arithmetic lookup to core_row_2
    core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);

    // a_hi set core_row_0.vers_25;
    // a_lo set core_row_0.vers_26;
    // d_hi set core_row_0.vers_27
    // d_lo set core_row_0.vers_28
    // sign_bit_is_zero_inv set core_row_0.vers_29;
    for (i, value) in (0..5).zip(signextend_result_vec) {
        assign_or_panic!(core_row_0[i + START_COL_IDX], value);
    }
    // Construct Witness object
    let bitwise_rows = bitwise_rows_vec
        .into_iter()
        .flat_map(|inner_vec| inner_vec.into_iter())
        .collect();

    (bitwise_rows, arithmetic_sub_rows)
}

/// signextend operations
/// Specify the `n`th `bit` as the symbol to perform sign bit extension on the `value`. The value range of n is 0~255
/// a is 2^n
/// value is the original value to be sign-bit extended
/// for specific calculation steps, please refer to the code comments.
pub fn signextend_by_bit<F: Field>(a: U256, value: U256) -> (Vec<U256>, Vec<Vec<bitwise::Row>>) {
    // calculate whether the `n`th `bit` of `value` is 0 or 1 based on `a` and `value`
    let a_lo: U256 = a.low_u128().into();
    let a_hi = a >> 128;
    let operand_1_hi_128 = value >> 128;
    let operand_1_lo_128: U256 = value.low_u128().into();
    let bitwise_rows1 = bitwise::Row::from_operation::<F>(
        bitwise::Tag::And,
        operand_1_hi_128.as_u128(),
        a_hi.as_u128(),
    );

    let bitwise_rows2 = bitwise::Row::from_operation::<F>(
        bitwise::Tag::And,
        operand_1_lo_128.as_u128(),
        a_lo.as_u128(),
    );

    // if bitwise sum is 0, it means that the position of shift is 0
    // if bitwise sum is not 0, it means that the position of shift is 1
    let sign_bit_is_zero =
        bitwise_rows1.last().unwrap().sum_2 + bitwise_rows2.last().unwrap().sum_2;

    // bitwise sum is byte+prev_byte, max_vaule is 2^7 * 32(2^12)
    let sign_bit_is_zero_inv = U256::from_little_endian(
        F::from_u128(sign_bit_is_zero.low_u128())
            .invert()
            .unwrap_or(F::ZERO)
            .to_repr()
            .as_ref(),
    );

    // get b
    // 1. a_lo = 0, then b_lo = 2^128 -1 ;
    // 2. a_lo <> 0, then b_lo = 2*a_lo -1 ;
    let max_u128 = U256::from(2).pow(U256::from(128)) - 1;
    let b_lo = if a_lo.is_zero() {
        max_u128.clone()
    } else {
        a_lo * 2 - 1
    };
    // 1. a_hi <> 0 , then b_hi = 2*a_hi -1
    // 2. a.hi = 0, a_lo = 0, then b_hi = 2^128 -1;
    // 3. a_hi = 0, a_lo <> 0, then b_hi = 0;
    let b_hi = if a_hi.is_zero() {
        if a_lo.is_zero() {
            max_u128.clone()
        } else {
            0.into()
        }
    } else {
        a_hi * 2 - 1
    };

    // get c
    // 1. if a_lo == 0 ,c_lo =0;
    // 2. if a_lo <> 0, c_lo = 2^128 - 2*a_lo
    let c_lo = if a_lo.is_zero() {
        0.into()
    } else {
        max_u128 + 1 - a_lo * 2
    };
    // get c_hi
    let c_hi = if a_hi.is_zero() {
        if a_lo.is_zero() {
            0.into()
        } else {
            max_u128
        }
    } else {
        max_u128 + 1 - a_hi * 2
    };

    // 1.  if sign_bit_is_zero is not 0 , then d = c, op_result = operand_1 || d
    // 2. if sign_bit_is_zero is 0, then d = b , op_result = operand_1 & d
    // get bitwise operator tag
    let (d_hi, d_lo, op_tag) = if sign_bit_is_zero.is_zero() {
        (b_hi, b_lo, bitwise::Tag::And)
    } else {
        (c_hi, c_lo, bitwise::Tag::Or)
    };

    // get bitwise rows
    // bitwise_rows3.acc[2] is result hi
    // bitwise_rows4.acc[2] is result lo
    let bitwise_rows3 =
        bitwise::Row::from_operation::<F>(op_tag, operand_1_hi_128.as_u128(), d_hi.as_u128());
    let bitwise_rows4 =
        bitwise::Row::from_operation::<F>(op_tag, operand_1_lo_128.as_u128(), d_lo.low_u128());
    (
        // calc result
        vec![a_hi, a_lo, d_hi, d_lo, sign_bit_is_zero_inv],
        // bitwise rows
        vec![bitwise_rows1, bitwise_rows2, bitwise_rows3, bitwise_rows4],
    )
}

macro_rules! assign_or_panic {
    ($opt: expr, $value: expr) => {
        match $opt {
            None => $opt = Some($value),
            Some(_) => panic!("Trying to assign to an already set Option!"),
        }
    };
}
pub(crate) use assign_or_panic;

impl core::Row {
    pub fn insert_exp_lookup(&mut self, base: U256, index: U256, power: U256) {
        let (expect_power, _) = base.overflowing_pow(index);
        assert_eq!(expect_power, power);
        let colum_values = [
            base >> 128,
            base.low_u128().into(),
            index >> 128,
            index.low_u128().into(),
            power >> 128,
            power.low_u128().into(),
        ];
        for i in 0..6 {
            assign_or_panic!(self[EXP_COLUMN_START_IDX + i], colum_values[i]);
        }
    }

    pub fn fill_versatile_with_values(&mut self, values: &[U256]) {
        for i in 0..NUM_VERS {
            assign_or_panic!(self[i], values[i]);
        }
    }

    /// insert_bitwise_lookup insert bitwise lookup ,5 columns in row prev(-2)
    /// originated from 10 col
    /// cnt = 2 can hold at most 4 bitwise operations (10 + 5*4)
    /// +---+-------+-------+-------+---------------------------------------------+
    /// |cnt| 8 col | 8 col | 8 col |              8 col                          |
    /// +---+-------+-------+-------+---------------------------------------------+
    /// | 2 | 10 col |      5*index    | TAG | ACC_0 | ACC_1 | ACC_2 | SUM_2 |2col|
    /// +---+-------+-------+-------+----------+
    pub fn insert_bitwise_lookups(&mut self, index: usize, bitwise_row: &bitwise::Row) {
        assert!(index <= 3);
        assert_eq!(self.cnt, 2.into());
        let column_values = [
            U256::from(bitwise_row.tag as u8),
            bitwise_row.acc_0,
            bitwise_row.acc_1,
            bitwise_row.acc_2,
            bitwise_row.sum_2,
        ];
        let start = BITWISE_COLUMN_START_IDX + BITWISE_COLUMN_WIDTH * index;
        for i in 0..BITWISE_COLUMN_WIDTH {
            assign_or_panic!(self[start + i], column_values[i]);
        }
        self.comments.extend([
            (
                format!("vers_{}", start),
                format!("tag:{:?}", bitwise_row.tag),
            ),
            (format!("vers_{}", start + 1), "acc_0".into()),
            (format!("vers_{}", start + 2), "acc_1".into()),
            (format!("vers_{}", start + 3), "acc_2".into()),
            (format!("vers_{}", start + 4), "sum_2".into()),
        ]);
    }
    pub fn insert_most_significant_byte_len_lookups(
        &mut self,
        index: usize,
        bitwise_row: &bitwise::Row,
    ) {
        assert!(index <= 3);
        assert_eq!(self.cnt, 2.into());
        let start = BITWISE_COLUMN_START_IDX + MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH * index;
        let column_values = [bitwise_row.acc_2, bitwise_row.index];
        for i in 0..MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH {
            assign_or_panic!(self[start + i], column_values[i]);
        }
        self.comments.extend([
            (format!("vers_{}", start), "acc_2".into()),
            (format!("vers_{}", start + 1), "index".into()),
        ]);
    }
    pub fn insert_state_lookups<const NUM_LOOKUP: usize>(
        &mut self,
        state_rows: [&state::Row; NUM_LOOKUP],
    ) {
        // this lookup must be in the row with this cnt
        assert!(NUM_LOOKUP <= 4);
        assert!(NUM_LOOKUP > 0);
        for (j, state_row) in state_rows.into_iter().enumerate() {
            assign_or_panic!(
                self[0 + j * STATE_COLUMN_WIDTH],
                (state_row.tag.unwrap_or_default() as u8).into()
            );
            assign_or_panic!(
                self[1 + j * STATE_COLUMN_WIDTH],
                state_row.stamp.unwrap_or_default()
            );
            assign_or_panic!(
                self[2 + j * STATE_COLUMN_WIDTH],
                state_row.value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[3 + j * STATE_COLUMN_WIDTH],
                state_row.value_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[4 + j * STATE_COLUMN_WIDTH],
                state_row.call_id_contract_addr.unwrap_or_default()
            );
            assign_or_panic!(
                self[5 + j * STATE_COLUMN_WIDTH],
                state_row.pointer_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[6 + j * STATE_COLUMN_WIDTH],
                state_row.pointer_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[7 + j * STATE_COLUMN_WIDTH],
                state_row.is_write.unwrap_or_default()
            );
            self.comments.extend([
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH),
                    format!("tag={:?}", state_row.tag),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 1),
                    "stamp".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 2),
                    "value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 3),
                    "value_lo".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 4),
                    "call_id".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 5),
                    "not used".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 6),
                    "stack pointer".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 7),
                    "is_write: read=0, write=1".into(),
                ),
            ]);
        }
    }

    // insert returndata size in cnt =3 row , fill column ranging from 0 to 7
    pub fn insert_returndata_size_state_lookup(&mut self, state_row: &state::Row) {
        assert_eq!(self.cnt, 3.into());
        assign_or_panic!(self[0], (state_row.tag.unwrap_or_default() as u8).into());
        assign_or_panic!(self[1], state_row.stamp.unwrap_or_default());
        assign_or_panic!(self[2], state_row.value_hi.unwrap_or_default());
        assign_or_panic!(self[3], state_row.value_lo.unwrap_or_default());
        assign_or_panic!(self[4], state_row.call_id_contract_addr.unwrap_or_default());
        assign_or_panic!(self[5], state_row.pointer_hi.unwrap_or_default());
        assign_or_panic!(self[6], state_row.pointer_lo.unwrap_or_default());
        assign_or_panic!(self[7], state_row.is_write.unwrap_or_default());
        self.comments.extend([
            (format!("vers_{}", 0), format!("tag={:?}", state_row.tag)),
            (format!("vers_{}", 1), "stamp".into()),
            (format!("vers_{}", 2), "value_hi".into()),
            (format!("vers_{}", 3), "value_lo".into()),
            (format!("vers_{}", 4), "call_id".into()),
            (format!("vers_{}", 5), "not used".into()),
            (format!("vers_{}", 6), "stack pointer".into()),
            (format!("vers_{}", 7), "is_write: read=0, write=1".into()),
        ]);
    }

    pub fn insert_storage_lookups<const NUM_LOOKUP: usize>(
        &mut self,
        state_rows: [&state::Row; NUM_LOOKUP],
    ) {
        assert!(NUM_LOOKUP < 3);
        assert!(NUM_LOOKUP > 0);
        for (j, state_row) in state_rows.into_iter().enumerate() {
            assign_or_panic!(
                self[0 + j * STORAGE_COLUMN_WIDTH],
                (state_row.tag.unwrap_or_default() as u8).into()
            );
            assign_or_panic!(
                self[1 + j * STORAGE_COLUMN_WIDTH],
                state_row.stamp.unwrap_or_default()
            );
            assign_or_panic!(
                self[2 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[3 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[4 + j * STORAGE_COLUMN_WIDTH],
                state_row.call_id_contract_addr.unwrap_or_default()
            );
            assign_or_panic!(
                self[5 + j * STORAGE_COLUMN_WIDTH],
                state_row.pointer_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[6 + j * STORAGE_COLUMN_WIDTH],
                state_row.pointer_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[7 + j * STORAGE_COLUMN_WIDTH],
                state_row.is_write.unwrap_or_default()
            );
            assign_or_panic!(
                self[8 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_pre_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[9 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_pre_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[10 + j * STORAGE_COLUMN_WIDTH],
                state_row.committed_value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[11 + j * STORAGE_COLUMN_WIDTH],
                state_row.committed_value_lo.unwrap_or_default()
            );
            self.comments.extend([
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH),
                    format!("tag={:?}", state_row.tag),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 1),
                    "stamp".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 2),
                    "value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 3),
                    "value_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 4),
                    "call_id".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 5),
                    "key_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 6),
                    "key_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 7),
                    "is_write: read=0, write=1".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 8),
                    "value_pre_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 9),
                    "value_pre_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 10),
                    "committed_value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 11),
                    "committed_value_lo".into(),
                ),
            ]);
        }
    }
    /// insert_stamp_cnt_lookups, include tag and cnt of state, tag always be EndPadding
    pub fn insert_stamp_cnt_lookups(&mut self, cnt: U256) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        assign_or_panic!(
            self[STAMP_CNT_COLUMN_START_IDX],
            U256::from(Tag::EndPadding as u8)
        );
        assign_or_panic!(self[STAMP_CNT_COLUMN_START_IDX + 1], cnt);

        #[rustfmt::skip]
		self.comments.extend([
			("vers_0".into(), "tag=EndPadding".into()),
			("vers_1".into(), "cnt".into()),
		]);
    }

    /// We can skip the constraint by setting code_addr to 0
    pub fn insert_bytecode_full_lookup(
        &mut self,
        pc: u64,
        opcode: OpcodeId,
        code_addr: U256,
        push_value: Option<U256>,
        not_code: bool,
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        for (i, value) in (0..8).zip([
            code_addr,
            pc.into(),
            opcode.as_u8().into(),
            (not_code as u8).into(),
            push_value.map_or(U256::zero(), |x| (x >> 128)),
            push_value.map_or(U256::zero(), |x| (x.low_u128().into())),
            opcode.data_len().into(),
            (opcode.is_push_with_data() as u8).into(),
        ]) {
            assign_or_panic!(self[BYTECODE_COLUMN_START_IDX + i], value);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", 24), "code_addr".into()),
			(format!("vers_{}", 25), "pc".into()),
			(format!("vers_{}", 26), format!("opcode={}", opcode)),
			(format!("vers_{}", 27), "non_code".into()),
			(format!("vers_{}", 28), "push_value_hi".into()),
			(format!("vers_{}", 29), "push_value_lo".into()),
			(format!("vers_{}", 30), "X for PUSHX".into()),
			(format!("vers_{}", 31), "is_push".into()),
		]);
    }

    pub fn insert_arithmetic_tiny_lookup(
        &mut self,
        index: usize,
        arith_entries: &[arithmetic::Row],
    ) {
        // in memory gas cost, arithmetic lookup needs to be placed on the cnt=1
        // assert_eq!(self.cnt, 2.into());
        assert!(index < 6);
        let arith_row = &arith_entries[arith_entries.len() - 1];
        let column_values = [
            arith_row.operand_0_hi,
            arith_row.operand_0_lo,
            arith_row.operand_1_hi,
            arith_row.operand_1_lo,
            (arith_row.tag as u8).into(),
        ];
        let offset = ARITHMETIC_TINY_START_IDX + index * ARITHMETIC_TINY_COLUMN_WIDTH;

        for i in 0..ARITHMETIC_TINY_COLUMN_WIDTH {
            assign_or_panic!(self[offset + i], column_values[i]);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", offset + 4), format!("arithmetic tag={:?}", arith_row.tag)),
		]);

        match arith_entries[0].tag {
            arithmetic::Tag::U64Overflow => {
                self.comments.extend([
                    (format!("vers_{}", offset), "value hi".into()),
                    (format!("vers_{}", offset + 1), "value lo".into()),
                    (format!("vers_{}", offset + 2), "w".into()),
                    (format!("vers_{}", offset + 3), "w_inv".into()),
                ]);
            }
            arithmetic::Tag::MemoryExpansion => {
                self.comments.extend([
                    (format!("vers_{}", offset), "offset".into()),
                    (format!("vers_{}", offset + 1), "memory_chunk_prev".into()),
                    (format!("vers_{}", offset + 2), "expansion_tag".into()),
                    (format!("vers_{}", offset + 3), "access_memory_size".into()),
                ]);
            }
            arithmetic::Tag::U64Div => {
                self.comments.extend([
                    (format!("vers_{}", offset), "numerator".into()),
                    (format!("vers_{}", offset + 1), "denominator".into()),
                    (format!("vers_{}", offset + 2), "quotient".into()),
                    (format!("vers_{}", offset + 3), "remainder".into()),
                ]);
            }
            _ => (),
        }
    }

    /// insert arithmetic_lookup insert arithmetic lookup, 9 columns in row prev(-2)
    /// row cnt = 2 can hold at most 3 arithmetic operations, 3 * 9 = 27
    /// +---+-------+-------+-------+-----+
    /// |cnt| 9 col | 9 col | 9 col |5 col|
    /// +---+-------+-------+-------+-----+
    /// | 2 | arith0|arith1 | arith2|     |
    /// +---+-------+-------+-------+-----+
    pub fn insert_arithmetic_lookup(&mut self, index: usize, arithmetic: &[arithmetic::Row]) {
        // this lookup must be in the row with this cnt
        assert!(index < 3);
        let len = arithmetic.len();
        assert!(len >= 2);
        let row_1 = &arithmetic[len - 2];
        let row_0 = &arithmetic[len - 1];
        let column_values = [
            row_0.operand_0_hi,
            row_0.operand_0_lo,
            row_0.operand_1_hi,
            row_0.operand_1_lo,
            row_1.operand_0_hi,
            row_1.operand_0_lo,
            row_1.operand_1_hi,
            row_1.operand_1_lo,
            (row_0.tag as u8).into(),
        ];
        let column_offset = index * ARITHMETIC_COLUMN_WIDTH;
        for i in 0..ARITHMETIC_COLUMN_WIDTH {
            assign_or_panic!(self[i + column_offset], column_values[i]);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH), "arithmetic operand 0 hi".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 1), "arithmetic operand 0 lo".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 2), "arithmetic operand 1 hi".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 3), "arithmetic operand 1 lo".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 8), format!("arithmetic tag={:?}", row_0.tag)),
		]);
        match row_0.tag {
            arithmetic::Tag::Add => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        "arithmetic sum hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        "arithmetic sum lo".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Addmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        format!("arithmetic operand modulus hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        format!("arithmetic operand modulus lo"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        format!("arithmetic remainder hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        format!("arithmetic remainder lo"),
                    ),
                ]);
            }
            arithmetic::Tag::Sub => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        "arithmetic difference hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        "arithmetic difference lo".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Mulmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        format!("arithmetic r hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        format!("arithmetic r lo"),
                    ),
                ]);
            }
            arithmetic::Tag::DivMod | arithmetic::Tag::SdivSmod => self.comments.extend([
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                    "arithmetic quotient hi".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                    "arithmetic quotient lo".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                    "arithmetic remainder hi".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                    "arithmetic remainder lo".into(),
                ),
            ]),
            arithmetic::Tag::Length => self.comments.extend([
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                    "arithmetic real_len".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                    "arithmetic zero_len".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                    "arithmetic real_len_is_zero".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                    "arithmetic zero_len_is_zero".into(),
                ),
            ]),
            _ => (),
        };
    }

    // insert_public_lookup insert public lookup ,6 columns
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub fn insert_public_lookup(&mut self, index: usize, public_row: &public::Row) {
        let column_values = [
            (public_row.tag as u8).into(),
            public_row.block_tx_idx.unwrap_or_default(),
            public_row.value_0.unwrap_or_default(),
            public_row.value_1.unwrap_or_default(),
            public_row.value_2.unwrap_or_default(),
            public_row.value_3.unwrap_or_default(),
        ];
        let start_idx = PUBLIC_COLUMN_START_IDX - index * PUBLIC_COLUMN_WIDTH;
        for i in 0..PUBLIC_COLUMN_WIDTH {
            assign_or_panic!(self[start_idx + i], column_values[i]);
        }
        let comments = vec![
            (
                format!("vers_{}", start_idx),
                format!("tag={:?}", public_row.tag),
            ),
            (format!("vers_{}", start_idx + 1), "block_tx_idx".into()),
            (format!("vers_{}", start_idx + 2), "value_0".into()),
            (format!("vers_{}", start_idx + 3), "value_1".into()),
            (format!("vers_{}", start_idx + 4), "value_2".into()),
            (format!("vers_{}", start_idx + 5), "value_3".into()),
        ];
        self.comments.extend(comments);
    }

    pub fn insert_copy_lookup(&mut self, index: usize, copy: &copy::Row) {
        // in row 2
        assert_eq!(self.cnt, 2.into());
        // max 2
        assert!(index < 2);
        let copy_values = vec![
            (copy.src_type as u8).into(),
            copy.src_id,
            copy.src_pointer,
            copy.src_stamp,
            (copy.dst_type as u8).into(),
            copy.dst_id,
            copy.dst_pointer,
            copy.dst_stamp,
            copy.cnt,
            copy.len,
            copy.acc,
        ];
        for i in 0..COPY_LOOKUP_COLUMN_CNT {
            assign_or_panic!(self[i + index * COPY_LOOKUP_COLUMN_CNT], copy_values[i]);
        }

        let comments = vec![
            // copy comment
            (
                format!("vers_{}", 0 + index * COPY_LOOKUP_COLUMN_CNT),
                format!("src_type={:?}", copy.src_type),
            ),
            (
                format!("vers_{}", 1 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_id".into(),
            ),
            (
                format!("vers_{}", 2 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_pointer".into(),
            ),
            (
                format!("vers_{}", 3 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_stamp".into(),
            ),
            (
                format!("vers_{}", 4 + index * COPY_LOOKUP_COLUMN_CNT),
                format!("dst_type={:?}", copy.dst_type),
            ),
            (
                format!("vers_{}", 5 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_id".into(),
            ),
            (
                format!("vers_{}", 6 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_pointer".into(),
            ),
            (
                format!("vers_{}", 7 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_stamp".into(),
            ),
            (
                format!("vers_{}", 8 + index * COPY_LOOKUP_COLUMN_CNT),
                "cnt".into(),
            ),
            (
                format!("vers_{}", 9 + index * COPY_LOOKUP_COLUMN_CNT),
                "len".into(),
            ),
            (
                format!("vers_{}", 10 + index * COPY_LOOKUP_COLUMN_CNT),
                "acc".into(),
            ),
        ];
        self.comments.extend(comments);
    }

    pub fn insert_log_left_selector(&mut self, log_left: usize) {
        assert_eq!(self.cnt, 1.into());
        simple_selector_assign(
            self,
            [
                LOG_SELECTOR_COLUMN_START_IDX + 4,
                LOG_SELECTOR_COLUMN_START_IDX + 3,
                LOG_SELECTOR_COLUMN_START_IDX + 2,
                LOG_SELECTOR_COLUMN_START_IDX + 1,
                LOG_SELECTOR_COLUMN_START_IDX,
            ],
            log_left,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        self.comments.extend([
            ("vers_8".into(), "LOG_LEFT_4 Selector (0/1)".into()),
            ("vers_9".into(), "LOG_LEFT_3 Selector (0/1)".into()),
            ("vers_10".into(), "LOG_LEFT_2 Selector (0/1)".into()),
            ("vers_11".into(), "LOG_LEFT_1 Selector (0/1)".into()),
            ("vers_12".into(), "LOG_LEFT_0 Selector (0/1)".into()),
        ]);
    }
}

impl Witness {
    pub fn append(&mut self, mut witness: Witness) {
        self.bytecode.append(&mut witness.bytecode);
        self.copy.append(&mut witness.copy);
        self.core.append(&mut witness.core);
        self.exp.append(&mut witness.exp);
        self.public.append(&mut witness.public);
        self.state.append(&mut witness.state);
        self.bitwise.append(&mut witness.bitwise);
        self.arithmetic.append(&mut witness.arithmetic);
        #[cfg(not(feature = "no_hash_circuit"))]
        self.keccak.append(&mut witness.keccak);
    }

    fn gen_bytecode_witness(
        addr: U256,
        mut machine_code: Vec<u8>,
        (hash_hi, hash_lo): (u128, u128),
    ) -> Vec<bytecode::Row> {
        let mut res = vec![];
        let mut pc = 0;
        let real_machine_code_len = machine_code.len();
        while pc < machine_code.len() {
            let op = OpcodeId::from(machine_code[pc]);
            let mut this_op = vec![];
            if op.is_push_with_data() {
                let mut cnt = (op.as_u64() - OpcodeId::PUSH0.as_u64()) as usize;
                // if pc >= machine_code.len(), the number of bytes pushed by the pushX instruction is less than X
                // then padding value
                if pc + cnt >= machine_code.len() {
                    let push_padding_zero_num = pc + cnt - machine_code.len() + 1;
                    machine_code.extend(vec![0; push_padding_zero_num]);
                    // add STOP
                    machine_code.push(OpcodeId::STOP.as_u8())
                }

                let mut acc_hi = 0u128;
                let mut acc_lo = 0u128;
                this_op.push(bytecode::Row {
                    addr: Some(addr),
                    pc: Some(pc.into()),
                    bytecode: Some(op.as_u64().into()),
                    acc_hi: Some(acc_hi.into()),
                    acc_lo: Some(acc_lo.into()),
                    cnt: Some(cnt.into()),
                    is_high: Some((if cnt >= 16 { 1 } else { 0 }).into()),
                    hash_hi: Some(hash_hi.into()),
                    hash_lo: Some(hash_lo.into()),
                    length: Some(real_machine_code_len.into()),
                    is_padding: Some(0.into()),
                    ..Default::default()
                });
                pc += 1;
                while cnt > 0 && pc < machine_code.len() {
                    cnt -= 1;
                    if cnt >= 16 {
                        acc_hi = acc_hi * 256 + machine_code[pc] as u128;
                    } else {
                        acc_lo = acc_lo * 256 + machine_code[pc] as u128;
                    }
                    this_op.push(bytecode::Row {
                        addr: Some(addr),
                        pc: Some(pc.into()),
                        bytecode: Some(machine_code[pc].into()),
                        acc_hi: Some(acc_hi.into()),
                        acc_lo: Some(acc_lo.into()),
                        cnt: Some(cnt.into()),
                        is_high: Some((if cnt >= 16 { 1 } else { 0 }).into()),
                        hash_hi: Some(hash_hi.into()),
                        hash_lo: Some(hash_lo.into()),
                        length: Some(real_machine_code_len.into()),
                        is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                        ..Default::default()
                    });
                    pc += 1;
                }
                let (value_hi, value_lo) = this_op.last().map(|x| (x.acc_hi, x.acc_lo)).unwrap();
                for i in &mut this_op {
                    i.value_hi = value_hi;
                    i.value_lo = value_lo;
                }
            } else {
                this_op.push(bytecode::Row {
                    addr: Some(addr),
                    pc: Some(pc.into()),
                    bytecode: Some(op.as_u64().into()),
                    cnt: Some(0.into()),
                    value_hi: Some(0.into()),
                    value_lo: Some(0.into()),
                    acc_hi: Some(0.into()),
                    acc_lo: Some(0.into()),
                    is_high: Some(0.into()),
                    hash_hi: Some(hash_hi.into()),
                    hash_lo: Some(hash_lo.into()),
                    length: Some(real_machine_code_len.into()),
                    is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                    ..Default::default()
                });
                pc += 1;
            }
            res.append(&mut this_op);
        }

        // to uniformly process all bytecodes, add padding to all bytecodes
        let all_zero_padding_num = BYTECODE_NUM_PADDING - (pc - real_machine_code_len);
        for _ in 0..all_zero_padding_num {
            res.push(bytecode::Row {
                addr: Some(addr),
                pc: Some(pc.into()),
                hash_hi: Some(hash_hi.into()),
                hash_lo: Some(hash_lo.into()),
                length: Some(real_machine_code_len.into()),
                is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                ..Default::default()
            });
            pc += 1;
        }
        res
    }

    /// Generate witness of all blocks related data, such as bytecode and public table
    fn insert_block_related(&mut self, chunk_data: &ChunkData) {
        self.public
            .append(&mut public::Row::from_chunk_data(&chunk_data).unwrap());
        let mut bytecode_set = HashSet::new();

        for account in chunk_data.blocks.iter().flat_map(|b| b.accounts.iter()) {
            let machine_code = account.code.as_ref();
            let code_hash = calc_keccak_hi_lo(machine_code);

            if !account.code.is_empty() && !bytecode_set.contains(&(account.address, code_hash)) {
                let mut bytecode_table =
                    Self::gen_bytecode_witness(account.address, machine_code.to_vec(), code_hash);
                // add to keccak_inputs
                #[cfg(not(feature = "no_hash_circuit"))]
                if machine_code.len() > 0 {
                    self.keccak.push(machine_code.to_vec());
                }
                self.bytecode.append(&mut bytecode_table);

                bytecode_set.insert((account.address, code_hash));
            }
        }
    }

    /// Generate begin padding of a witness of one block
    fn insert_begin_padding(&mut self) {
        // padding zero in the front
        (0..CoreCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows().0)
            .for_each(|_| self.core.insert(0, Default::default()));
        (0..BytecodeCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.bytecode.insert(0, Default::default()));
        (0..PublicCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.public.insert(0, Default::default()));
        (0..StateCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.state.insert(0, Default::default()));
        (0..CopyCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.copy.insert(0, Default::default()));
        (0..BitwiseCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.bitwise.insert(0, Default::default()));
        (0..ArithmeticCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.arithmetic.insert(0, Default::default()));
        (0..ExpCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.exp.insert(0, Default::default()));
    }

    /// Generate end_block of a witness of one block
    fn insert_end_block(
        &mut self,
        last_step: &GethExecStep,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let end_block_gadget = execution_gadgets_map
            .get(&ExecutionState::END_BLOCK)
            .unwrap();
        self.append(end_block_gadget.gen_witness(last_step, current_state));
    }

    /// Generate end padding of a witness of one chunk
    fn insert_end_padding(
        &mut self,
        last_step: &GethExecStep,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        // padding: add END_CHUNK to the end of core and (END_PADDING will be assigned automatically)
        let end_chunk_gadget = execution_gadgets_map
            .get(&ExecutionState::END_CHUNK)
            .unwrap();
        self.append(end_chunk_gadget.gen_witness(last_step, current_state));
    }

    fn insert_begin_chunk(
        &mut self,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let begin_chunk_gadget = execution_gadgets_map
            .get(&ExecutionState::BEGIN_CHUNK)
            .unwrap();
        self.append(begin_chunk_gadget.gen_witness(&GethExecStep::default(), current_state));
    }

    fn insert_begin_block(
        &mut self,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let begin_block_gadget = execution_gadgets_map
            .get(&ExecutionState::BEGIN_BLOCK)
            .unwrap();
        self.append(begin_block_gadget.gen_witness(&GethExecStep::default(), current_state));
    }

    /// Generate witness of one transaction's trace
    pub fn new(chunk_data: &ChunkData) -> Self {
        assert!(U256::from(usize::MAX) >= U256::from(u64::MAX), "struct Memory doesn't support evm's memory because the range of usize is smaller than that of u64");

        let execution_gadgets: Vec<
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        > = get_every_execution_gadgets!();
        let execution_gadgets_map = execution_gadgets
            .into_iter()
            .map(|gadget| (gadget.execution_state(), gadget))
            .collect();

        let mut witness = Witness::default();
        // step 1: insert all blocks related witness: bytecode and public
        witness.insert_block_related(&chunk_data);
        // step 2: insert padding to core, bytecode, state
        witness.insert_begin_padding();
        // step 3: create witness trace by trace, and append them
        let mut current_state = WitnessExecHelper::new();
        current_state.block_num_in_chunk = chunk_data.blocks.len();
        current_state.block_number_first_block = chunk_data
            .blocks
            .first()
            .unwrap()
            .eth_block
            .number
            .unwrap_or(1.into())
            .as_u64();
        current_state.chain_id = chunk_data.chain_id;

        // insert begin chunk
        witness.insert_begin_chunk(&mut current_state, &execution_gadgets_map);

        for (i, block) in chunk_data.blocks.iter().enumerate() {
            // initialize current_state per block
            current_state.initialize_each_block();

            let block_idx = i + 1;
            // set block_idx, txs number and log number in current_state with GethData
            current_state.block_idx = block_idx;
            current_state
                .tx_num_in_block
                .insert(block_idx, block.eth_block.transactions.len());
            current_state.log_num_in_block.insert(
                block_idx,
                block.logs.iter().map(|log_data| log_data.logs.len()).sum(),
            );
            current_state.timestamp = block.eth_block.timestamp;
            current_state.coinbase = block.eth_block.author.unwrap().as_bytes().into();
            current_state.block_gaslimit = block.eth_block.gas_limit;
            current_state.basefee = block.eth_block.base_fee_per_gas.unwrap();
            current_state.prevrandao = block.eth_block.mix_hash.unwrap().as_bytes().into();

            current_state.preprocess_storage(block);

            witness.insert_begin_block(&mut current_state, &execution_gadgets_map);

            for j in 0..block.geth_traces.len() {
                // initialize current_state per tx
                current_state.initialize_each_tx();

                let tx_idx = j + 1;
                let trace_related_witness =
                    current_state.generate_trace_witness(block, tx_idx, &execution_gadgets_map);
                witness.append(trace_related_witness);
            }
            // step 4: insert END_BLOCK
            witness.insert_end_block(
                block
                    .geth_traces
                    .last()
                    .and_then(|trace| trace.struct_logs.last())
                    .unwrap_or(&GethExecStep::default()),
                &mut current_state,
                &execution_gadgets_map,
            );
        }

        // step 5: insert end chunk
        witness.insert_end_padding(
            chunk_data
                .blocks
                .last()
                .and_then(|block| {
                    block
                        .geth_traces
                        .last()
                        .and_then(|trace| trace.struct_logs.last())
                })
                .unwrap_or(&GethExecStep::default()),
            &mut current_state,
            &execution_gadgets_map,
        );

        #[cfg(not(feature = "no_public_hash"))]
        // sort witness.public and fill in the values of cnt and length
        // some public rows generated by opcode gadgets
        public::witness_post_handle(&mut witness);

        #[cfg(all(
            not(feature = "no_public_hash_lookup"),
            not(feature = "no_public_hash")
        ))]
        // collect public keccak inputs
        witness
            .keccak
            .push(public::public_rows_hash_inputs(&witness.public));

        witness.state.sort_by(|a, b| {
            let key_a = state_to_be_limbs(a);
            let key_b = state_to_be_limbs(b);
            key_a.cmp(&key_b)
        });
        witness
    }

    pub fn write_all_as_csv<W: Write>(&self, writer: W) {
        let mut wtr = csv::Writer::from_writer(writer);
        let max_length = itertools::max([
            self.core.len(),
            self.bytecode.len(),
            self.state.len(),
            self.public.len(),
            self.arithmetic.len(),
            self.copy.len(),
            self.bitwise.len(),
            self.exp.len(),
        ])
        .unwrap();
        for i in 0..max_length {
            let core = self.core.get(i).cloned().unwrap_or_default();
            let state = self.state.get(i).cloned().unwrap_or_default();
            let bytecode = self.bytecode.get(i).cloned().unwrap_or_default();
            let public = self.public.get(i).cloned().unwrap_or_default();
            let arithmetic = self.arithmetic.get(i).cloned().unwrap_or_default();
            let copy = self.copy.get(i).cloned().unwrap_or_default();
            let bitwise = self.bitwise.get(i).cloned().unwrap_or_default();
            let exp = self.exp.get(i).cloned().unwrap_or_default();
            wtr.serialize((
                core, state, bytecode, public, arithmetic, copy, bitwise, exp,
            ))
            .unwrap()
        }
        wtr.flush().unwrap();
    }

    pub fn write_one_as_csv<W: Write, T: Serialize>(writer: W, table: &Vec<T>) {
        let mut wtr = csv::Writer::from_writer(writer);
        table.iter().for_each(|row| {
            wtr.serialize(row).unwrap();
        });
        wtr.flush().unwrap();
    }

    pub fn print_csv(&self) {
        let mut buf = Vec::new();
        self.write_all_as_csv(&mut buf);
        let csv_string = String::from_utf8(buf).unwrap();
        println!("{}", csv_string);
    }

    fn write_one_table<W: Write, T: Serialize, S: AsRef<str>>(
        &self,
        writer: &mut W,
        table: &Vec<T>,
        title: S,
        comments: Option<Vec<&HashMap<String, String>>>,
    ) {
        if table.is_empty() {
            println!("{} is empty!", title.as_ref());
            return;
        }
        let mut buf = Vec::new();
        Self::write_one_as_csv(&mut buf, table);
        let csv_string = String::from_utf8(buf).unwrap();

        writer.write(csv2html::start("").as_ref()).unwrap();
        writer.write(csv2html::caption(title).as_ref()).unwrap();
        let column_names: Vec<&str> = csv_string
            .lines()
            .next()
            .unwrap()
            .split(',')
            .into_iter()
            .collect();
        for (i_row, line) in csv_string.lines().enumerate() {
            let vec: Vec<String> = line.split(',').into_iter().map(|x| x.to_string()).collect();
            let mut col_attrs = vec![];
            if i_row > 0 {
                comments.as_ref().map(|x| {
                    let comments = x.get(i_row - 1).unwrap();
                    for i in 0..column_names.len() {
                        let comment = comments
                            .get(&column_names[i].to_string())
                            .map(|x| format!("title=\"{}\"", x))
                            .unwrap_or_default();
                        col_attrs.push(comment);
                    }
                });
            }
            writer
                .write(csv2html::row(&vec, i_row == 0, "".into(), &col_attrs).as_ref())
                .unwrap();
        }
        writer.write(csv2html::end().as_ref()).unwrap();
    }

    pub fn write_html<W: Write>(&self, mut writer: W) {
        writer
            .write(csv2html::prologue("Witness Table").as_ref())
            .unwrap();
        self.write_one_table(
            &mut writer,
            &self.core,
            "Core",
            Some(self.core.iter().map(|x| &x.comments).collect()),
        );
        self.write_one_table(&mut writer, &self.state, "State", None);
        self.write_one_table(&mut writer, &self.bytecode, "Bytecode", None);
        self.write_one_table(
            &mut writer,
            &self.public,
            "Public",
            Some(self.public.iter().map(|x| &x.comments).collect()),
        );
        self.write_one_table(&mut writer, &self.copy, "Copy", None);
        self.write_one_table(&mut writer, &self.exp, "Exp", None);
        self.write_one_table(&mut writer, &self.bitwise, "Bitwise", None);
        self.write_one_table(&mut writer, &self.arithmetic, "Arithmetic", None);
        writer.write(csv2html::epilogue().as_ref()).unwrap();
    }

    /// get_public_instance get instance from witness.public, return a vector of vector of F
    pub fn get_public_instance<F: Field>(&self) -> Vec<Vec<F>> {
        public_rows_to_instance(&self.public)
    }
}

impl ExecutionState {
    pub fn into_exec_state_core_row(
        self,
        trace: &GethExecStep,
        current_state: &WitnessExecHelper,
        num_hi: usize,
        num_lo: usize,
    ) -> core::Row {
        let state = self as usize;
        assert!(
            state < num_hi * num_lo,
            "state index {} >= selector size {} * {}",
            state,
            num_hi,
            num_lo
        );
        let (selector_hi, selector_lo) = get_dynamic_selector_assignments(state, num_hi, num_lo);
        let mut row = current_state.get_core_row_without_versatile(&trace, 0);
        row.exec_state = Some(self);

        let memory_chunk = match self {
            ExecutionState::CALL_1 | ExecutionState::CALL_2 | ExecutionState::CALL_3 => {
                current_state.memory_chunk_prev
            }
            _ => current_state.memory_chunk,
        };

        for (i, value) in
            (0..NUM_VERS)
                .into_iter()
                .zip(selector_hi.into_iter().chain(selector_lo).chain([
                    current_state.state_stamp,
                    current_state.stack_pointer as u64,
                    current_state.log_stamp,
                    current_state.gas_left,
                    trace.refund,
                    memory_chunk,
                    current_state.read_only,
                ]))
        {
            assign_or_panic!(row[i], value.into());
        }
        for i in 0..num_hi {
            row.comments
                .insert(format!("vers_{}", i), format!("dynamic selector hi {}", i));
        }
        for i in 0..num_lo {
            row.comments.insert(
                format!("vers_{}", num_hi + i),
                format!("dynamic selector lo {}", i),
            );
        }
        for (i, text) in DESCRIPTION_AUXILIARY.iter().enumerate() {
            row.comments
                .insert(format!("vers_{}", num_hi + num_lo + i), text.to_string());
        }
        row
    }
}

#[cfg(test)]
mod tests {
    use crate::util::chunk_data_test;

    use super::*;

    #[test]
    #[cfg(feature = "evm")]
    fn test_data_print_csv() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        witness.print_csv();
    }
}
