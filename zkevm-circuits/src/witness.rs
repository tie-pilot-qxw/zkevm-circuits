pub mod arithmetic;
pub mod bitwise;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fixed;
pub mod public;
pub mod state;

use crate::bitwise_circuit::BitwiseCircuit;
use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{
    DESCRIPTION_AUXILIARY, MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
};
use crate::copy_circuit::CopyCircuit;
use crate::core_circuit::CoreCircuit;
use crate::execution::{get_every_execution_gadgets, ExecutionGadget, ExecutionState};
use crate::state_circuit::ordering::state_to_be_limbs;
use crate::state_circuit::StateCircuit;
use crate::util::{
    convert_f_to_u256, convert_u256_to_f, create_contract_addr_with_prefix, uint64_with_overflow,
    SubCircuit,
};
use crate::witness::public::LogTag;
use crate::witness::state::{CallContextTag, Tag};
use eth_types::evm_types::{Memory, OpcodeId, Stack, Storage};
use eth_types::geth_types::GethData;
use eth_types::{Bytecode, Field, GethExecStep, U256};
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use gadgets::simple_seletor::simple_selector_assign;
use gadgets::util::Expr;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;

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
    // we omit fixed table rows on purpose due to its large size
}

pub struct WitnessExecHelper {
    pub stack_pointer: usize,
    pub parent_stack_pointer: HashMap<u64, usize>,
    pub call_data: HashMap<u64, Vec<u8>>,
    pub call_data_size: HashMap<u64, U256>,
    pub return_data: HashMap<u64, Vec<u8>>,
    pub value: HashMap<u64, U256>,
    pub sender: HashMap<u64, U256>,
    pub tx_idx: usize,
    pub call_id: u64,
    pub call_id_new: u64,
    pub parent_call_id: HashMap<u64, u64>,
    pub returndata_call_id: u64,
    pub returndata_size: U256,
    pub return_success: bool,
    pub code_addr: U256,
    pub parent_code_addr: HashMap<u64, U256>,
    pub storage_contract_addr: HashMap<u64, U256>,
    pub state_stamp: u64,
    pub log_stamp: u64,
    pub gas_left: u64,
    pub refund: u64,
    pub memory_chunk: u64,
    pub read_only: u64,
    pub bytecode: HashMap<U256, Bytecode>,
    /// The stack top of the next step, also the result of this step
    pub stack_top: Option<U256>,
    pub topic_left: usize,
    pub tx_value: U256,
    pub parent_pc: HashMap<u64, u64>,
}

impl WitnessExecHelper {
    pub fn new() -> Self {
        Self {
            stack_pointer: 0,
            parent_stack_pointer: HashMap::new(),
            call_data: HashMap::new(),
            call_data_size: HashMap::new(),
            return_data: HashMap::new(),
            value: HashMap::new(),
            sender: HashMap::new(),
            tx_idx: 0,
            call_id: 0,
            call_id_new: 0,
            parent_call_id: HashMap::new(),
            returndata_call_id: 0,
            returndata_size: 0.into(),
            return_success: false,
            code_addr: 0.into(),
            parent_code_addr: HashMap::new(),
            storage_contract_addr: HashMap::new(),
            state_stamp: 0,
            log_stamp: 0,
            gas_left: 0,
            refund: 0,
            memory_chunk: 0,
            read_only: 0,
            bytecode: HashMap::new(),
            stack_top: None,
            topic_left: 0,
            tx_value: 0.into(),
            parent_pc: HashMap::new(),
        }
    }

    pub fn update_from_next_step(&mut self, trace: &GethExecStep) {
        self.stack_top = trace.stack.0.last().cloned();
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
        let trace = &geth_data.geth_traces.get(tx_idx).unwrap().struct_logs;
        let tx = geth_data
            .eth_block
            .transactions
            .get(tx_idx)
            .expect("tx_idx out of bounds");
        let call_id = self.state_stamp + 1;
        assert_eq!(
            tx_idx, self.tx_idx,
            "the tx idx should match that in current_state"
        );
        // due to we decide to start idx at 1 in witness
        let tx_idx = tx_idx + 1;
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
        if tx.to.is_some() {
            self.call_data.insert(call_id, tx.input.to_vec());
        }
        self.call_data_size
            .insert(call_id, self.call_data[&call_id].len().into());

        self.value.insert(call_id, tx.value);
        self.tx_value = tx.value;
        self.sender.insert(call_id, tx.from.as_bytes().into());
        self.code_addr = to;
        self.bytecode = bytecode;

        let mut res: Witness = Default::default();
        let first_step = trace.first().unwrap(); // not actually used in BEGIN_TX_1 and BEGIN_TX_2
        let last_step = trace.last().unwrap(); // not actually used in END_CALL and END_TX
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_1)
                .unwrap()
                .gen_witness(first_step, self),
        );
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_2)
                .unwrap()
                .gen_witness(first_step, self),
        );
        let mut iter_for_next_step = trace.iter();
        iter_for_next_step.next();
        for step in trace {
            if let Some(next_step) = iter_for_next_step.next() {
                self.update_from_next_step(next_step);
            }
            res.append(self.generate_execution_witness(step, &execution_gadgets_map))
        }
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::END_CALL)
                .unwrap()
                .gen_witness(last_step, self),
        );
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
    ) -> Witness {
        let mut res = Witness::default();
        let execution_states = ExecutionState::from_opcode(trace_step.op);
        for execution_state in execution_states {
            if let Some(gadget) = execution_gadgets_map.get(&execution_state) {
                res.append(gadget.gen_witness(trace_step, self));
            } else {
                panic!("execution state {:?} not supported yet", execution_state);
            }
        }
        res
    }

    pub fn get_core_row_without_versatile(
        &self,
        trace_step: &GethExecStep,
        multi_row_cnt: usize,
    ) -> core::Row {
        core::Row {
            tx_idx: self.tx_idx.into(),
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
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(self.stack_pointer.into()),
            is_write: Some(0.into()),
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
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer - index_start_at_1 + 1).into()), // stack pointer start at 1, hence +1
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, *value)
    }

    pub fn get_memory_read_row(&mut self, trace_step: &GethExecStep, dst: usize) -> state::Row {
        let value = trace_step.memory.0.get(dst).cloned().unwrap_or_default();
        let res = state::Row {
            tag: Some(state::Tag::Memory),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_memory_write_row(&mut self, dst: usize, value: u8) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::Memory),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_return_data_read_row(&mut self, dst: usize, call_id: u64) -> (state::Row, u8) {
        let value = self
            .return_data
            .get(&call_id)
            .unwrap()
            .get(dst)
            .cloned()
            .unwrap_or_default();
        let res = state::Row {
            tag: Some(state::Tag::ReturnData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_return_data_write_row(&mut self, dst: usize, value: u8) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::ReturnData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(value.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(1.into()),
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
            tag: Some(state::Tag::Storage),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some(value >> 128),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(contract_addr),
            pointer_hi: Some(key >> 128),
            pointer_lo: Some(key.low_u128().into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_call_context_read_row(&mut self, trace_step: &GethExecStep) -> (state::Row, U256) {
        let (value, tag) = match trace_step.op {
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
            _ => {
                panic!("not CALLDATASIZE,CALLER or CALLVALUE")
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
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_call_context_write_row(
        &mut self,
        tag: state::CallContextTag,
        value: U256,
        call_id: u64,
    ) -> (state::Row) {
        let res = state::Row {
            tag: Some(Tag::CallContext),
            stamp: Some(self.state_stamp.into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((tag as usize).into()),
            is_write: Some(1.into()),
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
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer + 1).into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        self.stack_pointer += 1;
        res
    }

    pub fn get_overwrite_stack_row(
        &mut self,
        trace_step: &GethExecStep,
        index_start_at_1: usize,
        value: U256,
    ) -> state::Row {
        let len = trace_step.stack.0.len();
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer - index_start_at_1 + 1).into()), // stack pointer start at 1, hence +1
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_code_copy_rows<F: Field>(
        &mut self,
        address: U256,
        dst: U256,
        src: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>, u64, u64, u64) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        // way of processing address and src and len, reference go-ethereum's method
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go#L373
        // src offset check
        let mut src_offset: u64 = 0;
        if uint64_with_overflow(&src) {
            src_offset = u64::MAX;
        } else {
            src_offset = src.as_u64();
        }
        let dst_offset = dst.low_u64();
        let length = len.low_u64();
        let codecopy_stamp = self.state_stamp;
        let code = self.bytecode.get(&address).unwrap();
        let code_length = code.code.len() as u64;
        let mut padding_length: u64 = 0;
        let mut code_copy_length: u64 = 0;
        if length > 0 {
            if src_offset >= code_length {
                padding_length = length;
            } else {
                if length > code_length - src_offset {
                    padding_length = length - (code_length - src_offset);
                    code_copy_length = code_length - src_offset;
                } else {
                    code_copy_length = length;
                }
            }
        }
        if code_copy_length > 0 {
            let mut acc_pre = U256::from(0);
            let temp_256_f = F::from(256);
            for i in 0..code_copy_length {
                let code = self.bytecode.get(&address).unwrap();
                let byte = code.get((src_offset + i) as usize).unwrap().value;

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
                    len: code_copy_length.into(),
                    acc: acc,
                });
                state_rows.push(self.get_memory_write_row((dst_offset + i) as usize, byte));
            }
        }
        let codecopy_padding_stamp = self.state_stamp;
        if padding_length > 0 {
            for i in 0..padding_length {
                state_rows.push(
                    self.get_memory_write_row(
                        (dst_offset + code_copy_length + i) as usize,
                        0 as u8,
                    ),
                );
                copy_rows.push(copy::Row {
                    byte: 0.into(),
                    src_type: copy::Tag::Zero,
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::Memory,
                    dst_id: self.call_id.into(),
                    dst_pointer: (dst_offset + code_copy_length).into(),
                    dst_stamp: codecopy_padding_stamp.into(),
                    cnt: i.into(),
                    len: U256::from(padding_length),
                    acc: 0.into(),
                })
            }
        }

        (
            copy_rows,
            state_rows,
            length,
            padding_length,
            code_copy_length,
        )
    }

    pub fn get_call_return_data_copy_rows<F: Field>(
        &mut self,
        dst: U256,
        len: U256,
    ) -> (Vec<copy::Row>, Vec<state::Row>, u64) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        // way of processing len, reference go-ethereum's method
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go#L664

        let dst_offset = dst.low_u64();
        let length = len.low_u64();
        let copy_stamp = self.state_stamp;
        let return_data_length = self
            .return_data
            .get(&self.returndata_call_id)
            .unwrap()
            .len() as u64;
        let mut copy_length: u64 = 0;

        if length > return_data_length {
            copy_length = return_data_length;
        } else {
            copy_length = length;
        }

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
                    acc: acc,
                });
                state_rows.push(
                    self.get_return_data_read_row(i as usize, self.returndata_call_id)
                        .0,
                );
            }

            for i in 0..copy_length {
                let return_data = self.return_data.get(&self.returndata_call_id).unwrap();
                let byte = return_data.get(i as usize).cloned().unwrap_or_default();
                state_rows.push(self.get_memory_write_row((dst_offset + i) as usize, byte));
            }
        }

        (copy_rows, state_rows, copy_length)
    }

    pub fn get_return_data_copy_rows<F: Field>(
        &mut self,
        dst: usize,
        src: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        //TODO: src_id need use last_call_id (return_data_write maybe use last_call_id )
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        let dst_copy_stamp = self.state_stamp + len as u64;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);
        for i in 0..len {
            // todo situations to deal: 1. if according to address ,get nil ;2. or return_data is not long enough
            let data = self.return_data.get(&self.call_id).unwrap();
            let byte = data.get(src + i).cloned().unwrap();

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
                src_id: self.call_id.into(),
                src_pointer: src.into(),
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: dst.into(),
                dst_stamp: dst_copy_stamp.into(),
                cnt: i.into(),
                len: len.into(),
                acc: acc,
            });

            state_rows.push(self.get_return_data_read_row(src + i, self.call_id).0);
        }

        for i in 0..len {
            // todo situations to deal: 1. if according to address ,get nil ;2. or return_data is not long enough
            let data = self.return_data.get(&self.call_id).unwrap();
            let byte = data.get(src + i).cloned().unwrap();

            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }

        (copy_rows, state_rows)
    }
    pub fn get_calldata_read_row(&mut self, dst: usize) -> (state::Row, u8) {
        let val = self.call_data[&self.call_id]
            .get(dst)
            .cloned()
            .unwrap_or_default();
        let state_row = state::Row {
            tag: Some(state::Tag::CallData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(val.into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (state_row, val)
    }

    pub fn get_calldata_write_row(
        &mut self,
        dst: usize,
        val: u8,
        dst_call_id: u64,
    ) -> (state::Row) {
        let state_row = state::Row {
            tag: Some(state::Tag::CallData),
            stamp: Some(self.state_stamp.into()),
            value_hi: None,
            value_lo: Some(val.into()),
            call_id_contract_addr: Some(dst_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some(dst.into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        state_row
    }

    pub fn get_calldata_copy_rows<F: Field>(
        &mut self,
        dst: usize,
        src: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..len {
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
                src_pointer: src.into(),
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: dst.into(),
                dst_stamp: (copy_stamp + len as u64).into(),
                cnt: i.into(),
                len: len.into(),
                acc: acc,
            });
            state_rows.push(state_row);
        }

        for i in 0..len {
            let call_data = self.call_data.get(&self.call_id).unwrap();
            let byte = call_data.get(src + i).cloned().unwrap_or_default();
            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }

        (copy_rows, state_rows)
    }

    pub fn get_calldata_write_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        args_offset: usize,
        args_len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        let mut calldata_new = vec![];

        for i in 0..args_len {
            let byte = trace
                .memory
                .0
                .get(args_offset + i)
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
                dst_stamp: (copy_stamp + args_len as u64).into(),
                cnt: i.into(),
                len: args_len.into(),
                acc: acc,
            });
            state_rows.push(self.get_memory_read_row(trace, args_offset + i));
        }

        for i in 0..args_len {
            state_rows.push(self.get_calldata_write_row(i, calldata_new[i], self.call_id_new));
        }

        self.call_data.insert(self.call_id_new, calldata_new);

        (copy_rows, state_rows)
    }

    pub fn get_calldata_load_rows(&mut self, idx: usize, length: usize) -> Vec<state::Row> {
        let mut state_rows = vec![];
        let call_data = &self.call_data[&self.call_id];
        let len = if idx + length <= call_data.len() {
            idx + length
        } else {
            call_data.len()
        };
        // data
        for (i, &byte) in call_data[idx..len].iter().enumerate() {
            state_rows.push(state::Row {
                tag: Some(state::Tag::CallData),
                stamp: Some(self.state_stamp.into()),
                value_hi: None,
                value_lo: Some(byte.into()),
                call_id_contract_addr: Some(self.call_id.into()),
                pointer_hi: None,
                pointer_lo: Some(i.into()),
                is_write: Some(0.into()),
            });
            self.state_stamp += 1;
        }
        // padding
        if call_data.len() < length {
            for i in call_data.len()..length {
                state_rows.push(state::Row {
                    tag: Some(state::Tag::CallData),
                    stamp: Some(self.state_stamp.into()),
                    value_hi: None,
                    value_lo: None,
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    pointer_lo: None,
                    is_write: Some(0.into()),
                });
                self.state_stamp += 1;
            }
        }
        state_rows
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

            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Tag::PublicCalldata,
                src_id: self.tx_idx.into(),
                src_pointer: 0.into(),
                src_stamp: 0.into(),
                dst_type: copy::Tag::Calldata,
                dst_id: self.call_id.into(),
                dst_pointer: 0.into(),
                dst_stamp: stamp_start.into(),
                cnt: i.into(),
                len: len.into(),
                acc: acc,
            });
            state_rows.push(state::Row {
                tag: Some(state::Tag::CallData),
                stamp: Some(self.state_stamp.into()),
                value_hi: None,
                value_lo: Some(byte.into()),
                call_id_contract_addr: Some(self.call_id.into()),
                pointer_hi: None,
                pointer_lo: Some(i.into()),
                is_write: Some(1.into()),
            });
            self.state_stamp += 1;
        }
        (copy_rows, state_rows)
    }

    ///load 32-bytes value from memory
    pub fn get_mload_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let mut stamp_start = self.state_stamp;
        let mut offset_start = offset;

        let temp_256_f = F::from(256);

        for i in 0..2 {
            let mut acc_pre = U256::from(0);
            for j in 0..16 {
                let byte = trace
                    .memory
                    .0
                    .get(offset_start + j)
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
                    src_pointer: offset_start.into(),
                    src_stamp: stamp_start.into(),
                    dst_type: copy::Tag::Null,
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: j.into(),
                    len: 16.into(),
                    acc: acc,
                });
                state_rows.push(state::Row {
                    tag: Some(state::Tag::Memory),
                    stamp: Some((stamp_start + j as u64).into()),
                    value_hi: None,
                    value_lo: Some(byte.into()),
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    pointer_lo: Some((offset_start + j).into()),
                    is_write: Some(0.into()),
                });
                self.state_stamp += 1;
            }
            stamp_start += 16;
            offset_start += 16;
        }

        (copy_rows, state_rows)
    }

    pub fn get_mstore_rows<F: Field>(
        &mut self,
        offset: usize,
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
                    dst_pointer: offset_start.into(),
                    dst_stamp: stamp_start.into(),
                    cnt: j.into(),
                    len: 16.into(),
                    acc: acc,
                });
                state_rows.push(state::Row {
                    tag: Some(state::Tag::Memory),
                    stamp: Some((stamp_start + j as u64).into()),
                    value_hi: None,
                    value_lo: Some(byte.into()),
                    call_id_contract_addr: Some(self.call_id.into()),
                    pointer_hi: None,
                    pointer_lo: Some((offset_start + j).into()),
                    is_write: Some(1.into()),
                });
                self.state_stamp += 1;
            }
            stamp_start += 16;
            offset_start += 16;
        }

        (copy_rows, state_rows)
    }

    /// Load calldata from public table to state table
    pub fn get_write_call_context_row(
        &mut self,
        value_hi: Option<U256>,
        value_lo: Option<U256>,
        context_tag: state::CallContextTag,
    ) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi,
            value_lo,
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((context_tag as u8).into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_return_revert_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        let dst_copy_stamp = self.state_stamp + len as u64;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..len {
            let byte = trace.memory.0.get(offset + i).cloned().unwrap_or_default();

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
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::Returndata,
                dst_id: self.call_id.into(),
                dst_pointer: 0.into(),
                dst_stamp: dst_copy_stamp.into(),
                cnt: i.into(),
                len: len.into(),
                acc: acc,
            });
            state_rows.push(self.get_memory_read_row(trace, offset + i));
        }
        for i in 0..len {
            let byte = trace.memory.0.get(offset + i).cloned().unwrap_or_default();
            state_rows.push(self.get_return_data_write_row(i, byte));
        }

        (copy_rows, state_rows)
    }
    pub fn get_returndata_call_id_row(&mut self) -> state::Row {
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: None,
            value_lo: Some(self.returndata_call_id.into()),
            call_id_contract_addr: None,
            pointer_hi: None,
            pointer_lo: Some((state::CallContextTag::ReturnDataCallId as u8).into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        res
    }
    pub fn get_returndata_size_row(&mut self) -> (state::Row, U256) {
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((self.returndata_size >> 128).as_u128().into()),
            value_lo: Some(self.returndata_size.low_u128().into()),
            call_id_contract_addr: Some(self.returndata_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((state::CallContextTag::ReturnDataSize as u8).into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, self.returndata_size.into())
    }
    pub fn get_storage_contract_addr_row(&mut self) -> (state::Row, U256) {
        let value = self.storage_contract_addr.get(&self.call_id).unwrap();
        let res = state::Row {
            tag: Some(state::Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value.clone() >> 128).as_u128().into()),
            value_lo: Some(value.clone().low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((state::CallContextTag::StorageContractAddr as u8).into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, value.clone())
    }

    pub fn get_log_bytes_rows<F: Field>(
        &mut self,
        trace: &GethExecStep,
        offset: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let copy_stamp = self.state_stamp;
        let log_stamp = self.log_stamp;

        let mut acc_pre = U256::from(0);
        let temp_256_f = F::from(256);

        for i in 0..len {
            let byte = trace.memory.0.get(offset + i).cloned().unwrap_or_default();

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
                src_stamp: copy_stamp.into(),
                dst_type: copy::Tag::PublicLog,
                dst_id: self.tx_idx.into(), // tx_idx
                dst_pointer: 0.into(),      // PublicLog index
                dst_stamp: log_stamp.into(),
                cnt: i.into(),
                len: len.into(),
                acc,
            });
            state_rows.push(self.get_memory_read_row(trace, offset + i));
        }

        (copy_rows, state_rows)
    }

    // core_row_1.vers_26 ~ vers31
    pub fn get_public_log_data_size_row(&self, data_len: U256) -> public::Row {
        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), format!("tx_idx"));
        comments.insert(format!("vers_{}", 28), format!("log_index"));
        comments.insert(format!("vers_{}", 29), format!("log tag={}", "DataSize"));
        comments.insert(format!("vers_{}", 30), format!("0"));
        comments.insert(format!("vers_{}", 31), format!("data_len"));

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            tx_idx_or_number_diff: Some(U256::from(self.tx_idx as u64)),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(LogTag::DataSize as u64)),
            value_2: Some(0.into()),
            value_3: Some(data_len),
            comments,
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
        comments.insert(format!("vers_{}", 27), format!("tx_idx"));
        comments.insert(format!("vers_{}", 28), format!("log_index"));
        comments.insert(
            format!("vers_{}", 29),
            format!("topic_log_tag={}", topic_tag),
        );
        comments.insert(format!("vers_{}", 30), format!("topic_hash[..16]"));
        comments.insert(format!("vers_{}", 31), format!("topic_hash[16..]"));

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            tx_idx_or_number_diff: Some(U256::from(self.tx_idx as u64)),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(topic_log_tag as u64)),
            value_2: topic_hash_hi, // topic_hash[..16]
            value_3: topic_hash_lo, // topic_hash[16..]
            comments,
        };

        public_row
    }

    pub fn get_public_log_topic_num_addr_row(&self, opcode_id: OpcodeId) -> public::Row {
        let mut log_tag: LogTag;
        let mut log_tag_name: &str;

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
        let value_hi = (self.code_addr >> 128).as_u128();
        let value_lo = self.code_addr.low_u128();

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), format!("tx_idx"));
        comments.insert(format!("vers_{}", 28), format!("log_index"));
        comments.insert(format!("vers_{}", 29), format!("log_tag={}", log_tag_name));
        comments.insert(format!("vers_{}", 30), format!("address[..4]"));
        comments.insert(format!("vers_{}", 31), format!("address[4..]"));

        let public_row = public::Row {
            tag: public::Tag::TxLog,
            tx_idx_or_number_diff: Some(U256::from(self.tx_idx as u64)),
            value_0: Some(U256::from(self.log_stamp)),
            value_1: Some(U256::from(log_tag as u64)),
            value_2: Some(U256::from(value_hi)),
            value_3: Some(U256::from(value_lo)),
            comments,
        };
        public_row
    }
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
        // todo: exp overflow
        let (expect_power, _) = base.overflowing_pow(index);
        assert_eq!(expect_power, power);
        assign_or_panic!(self.vers_26, base >> 128);
        assign_or_panic!(self.vers_27, base.low_u128().into());
        assign_or_panic!(self.vers_28, index >> 128);
        assign_or_panic!(self.vers_29, index.low_u128().into());
        assign_or_panic!(self.vers_30, power >> 128);
        assign_or_panic!(self.vers_31, power.low_u128().into());
    }

    pub fn fill_versatile_with_values(&mut self, values: &[U256]) {
        #[rustfmt::skip]
            let cells = [
            &mut self.vers_0, &mut self.vers_1, &mut self.vers_2, &mut self.vers_3, &mut self.vers_4, &mut self.vers_5, &mut self.vers_6, &mut self.vers_7,
            &mut self.vers_8, &mut self.vers_9, &mut self.vers_10, &mut self.vers_11, &mut self.vers_12, &mut self.vers_13, &mut self.vers_14, &mut self.vers_15,
            &mut self.vers_16, &mut self.vers_17, &mut self.vers_18, &mut self.vers_19, &mut self.vers_20, &mut self.vers_21, &mut self.vers_22, &mut self.vers_23,
            &mut self.vers_24, &mut self.vers_25, &mut self.vers_26, &mut self.vers_27, &mut self.vers_28, &mut self.vers_29, &mut self.vers_30, &mut self.vers_31
        ];
        for (cell, v) in cells.into_iter().zip(values) {
            assign_or_panic!(*cell, *v);
        }
    }

    pub fn insert_bitwise_op_tag(&mut self, tag: usize) {
        assign_or_panic!(self.vers_25, tag.into());
    }
    /// insert_bitwise_lookup insert bitwise lookup ,5 columns in row prev(-2)
    ///
    /// cnt = 2 can hold at most 6 bitwise operations
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 8 col |
    /// +---+-------+-------+-------+----------+
    /// | 2 | 5*num | TAG | ACC_0 | ACC_1 | ACC_2 | SUM_2 |
    /// +---+-------+-------+-------+----------+
    pub fn insert_bitwise_lookups(&mut self, index: usize, bitwise_row: &bitwise::Row) {
        assert!(index <= 5);
        assert_eq!(self.cnt, 2.into());
        #[rustfmt::skip]
            let  vec = [
            [&mut self.vers_0, &mut self.vers_1, &mut self.vers_2, &mut self.vers_3, &mut self.vers_4,],
            [&mut self.vers_5, &mut self.vers_6, &mut self.vers_7, &mut self.vers_8, &mut self.vers_9,],
            [&mut self.vers_10, &mut self.vers_11, &mut self.vers_12, &mut self.vers_13, &mut self.vers_14,],
            [&mut self.vers_15, &mut self.vers_16, &mut self.vers_17, &mut self.vers_18, &mut self.vers_19,],
            [&mut self.vers_20, &mut self.vers_21, &mut self.vers_22, &mut self.vers_23, &mut self.vers_24,],
            [&mut self.vers_25, &mut self.vers_26, &mut self.vers_27, &mut self.vers_28, &mut self.vers_29,],
        ];
        assign_or_panic!(*vec[index][0], U256::from(bitwise_row.tag as u8));
        assign_or_panic!(*vec[index][1], bitwise_row.acc_0);
        assign_or_panic!(*vec[index][2], bitwise_row.acc_1);
        assign_or_panic!(*vec[index][3], bitwise_row.acc_2);
        assign_or_panic!(*vec[index][4], bitwise_row.sum_2);
        self.comments.extend([
            (
                format!("vers_{}", index * 5),
                format!("tag:{:?}", bitwise_row.tag),
            ),
            (format!("vers_{}", index * 5 + 1), format!("acc_0")),
            (format!("vers_{}", index * 5 + 2), format!("acc_1")),
            (format!("vers_{}", index * 5 + 3), format!("acc_2")),
            (format!("vers_{}", index * 5 + 4), format!("sum_2")),
        ]);
    }
    pub fn insert_state_lookups<const NUM_LOOKUP: usize>(
        &mut self,
        state_rows: [&state::Row; NUM_LOOKUP],
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        assert!(NUM_LOOKUP <= 4);
        assert!(NUM_LOOKUP > 0);
        #[rustfmt::skip]
            let vec = [
            [&mut self.vers_0, &mut self.vers_1, &mut self.vers_2, &mut self.vers_3, &mut self.vers_4, &mut self.vers_5, &mut self.vers_6, &mut self.vers_7],
            [&mut self.vers_8, &mut self.vers_9, &mut self.vers_10, &mut self.vers_11, &mut self.vers_12, &mut self.vers_13, &mut self.vers_14, &mut self.vers_15],
            [&mut self.vers_16, &mut self.vers_17, &mut self.vers_18, &mut self.vers_19, &mut self.vers_20, &mut self.vers_21, &mut self.vers_22, &mut self.vers_23],
            [&mut self.vers_24, &mut self.vers_25, &mut self.vers_26, &mut self.vers_27, &mut self.vers_28, &mut self.vers_29, &mut self.vers_30, &mut self.vers_31]
        ];
        for (n, (state_row, core_row)) in state_rows.into_iter().zip(vec).enumerate() {
            for i in 0..8 {
                // before inserting, these columns must be none
                assert!(core_row[i].is_none());
            }
            *core_row[0] = state_row.tag.map(|tag| (tag as u8).into());
            *core_row[1] = state_row.stamp;
            *core_row[2] = state_row.value_hi;
            *core_row[3] = state_row.value_lo;
            *core_row[4] = state_row.call_id_contract_addr;
            *core_row[5] = state_row.pointer_hi;
            *core_row[6] = state_row.pointer_lo;
            *core_row[7] = state_row.is_write;
            #[rustfmt::skip]
            self.comments.extend([
                (format!("vers_{}", n * 8), format!("tag={:?}", state_row.tag)),
                (format!("vers_{}", n * 8 + 1), format!("stamp")),
                (format!("vers_{}", n * 8 + 2), format!("value_hi")),
                (format!("vers_{}", n * 8 + 3), format!("value_lo")),
                (format!("vers_{}", n * 8 + 4), format!("call_id")),
                (format!("vers_{}", n * 8 + 5), format!("not used")),
                (format!("vers_{}", n * 8 + 6), format!("stack pointer")),
                (format!("vers_{}", n * 8 + 7), format!("is_write: read=0, write=1")),
            ]);
        }
    }

    /// We can skip the constraint by setting code_addr to 0
    pub fn insert_bytecode_full_lookup(
        &mut self,
        pc: u64,
        opcode: OpcodeId,
        code_addr: U256,
        push_value: Option<U256>,
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());

        for (cell, value) in [
            &mut self.vers_24,
            &mut self.vers_25,
            &mut self.vers_26,
            &mut self.vers_27,
            &mut self.vers_28,
            &mut self.vers_29,
            &mut self.vers_30,
            &mut self.vers_31,
        ]
        .into_iter()
        .zip([
            Some(code_addr),
            Some(pc.into()),
            Some(opcode.as_u8().into()),
            Some(0.into()), // non_code must be 0
            push_value.map(|x| (x >> 128).as_u128().into()),
            push_value.map(|x| (x.low_u128().into())),
            Some(opcode.data_len().into()),
            Some((opcode.is_push() as u8).into()),
        ]) {
            // before inserting, these columns must be none
            assert!(cell.is_none());
            *cell = value;
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", 24), format!("code_addr")),
            (format!("vers_{}", 25), format!("pc")),
            (format!("vers_{}", 26), format!("opcode={}", opcode)),
            (format!("vers_{}", 27), format!("non_code must be 0")),
            (format!("vers_{}", 28), format!("push_value_hi")),
            (format!("vers_{}", 29), format!("push_value_lo")),
            (format!("vers_{}", 30), format!("X for PUSHX")),
            (format!("vers_{}", 31), format!("is_push")),
        ]);
    }

    pub fn insert_arithmetic_lookup(&mut self, arithmetic: &[arithmetic::Row]) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 2.into());
        let len = arithmetic.len();
        assert!(len >= 2);
        let row_0 = &arithmetic[len - 1];
        let row_1 = &arithmetic[len - 2];

        for (cell, value) in [
            (&mut self.vers_0, row_0.operand_0_hi),
            (&mut self.vers_1, row_0.operand_0_lo),
            (&mut self.vers_2, row_0.operand_1_hi),
            (&mut self.vers_3, row_0.operand_1_lo),
            (&mut self.vers_4, row_1.operand_0_hi),
            (&mut self.vers_5, row_1.operand_0_lo),
            (&mut self.vers_6, row_1.operand_1_hi),
            (&mut self.vers_7, row_1.operand_1_lo),
            (&mut self.vers_8, (row_0.tag as u8).into()),
        ] {
            assign_or_panic!(*cell, value);
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", 0), format!("arithmetic operand 0 hi")),
            (format!("vers_{}", 1), format!("arithmetic operand 0 lo")),
            (format!("vers_{}", 2), format!("arithmetic operand 1 hi")),
            (format!("vers_{}", 3), format!("arithmetic operand 1 lo")),
            (format!("vers_{}", 8), format!("arithmetic tag={:?}", row_0.tag)),
        ]);
        match row_0.tag {
            arithmetic::Tag::Add => {
                self.comments.extend([
                    (format!("vers_{}", 4), format!("arithmetic sum hi")),
                    (format!("vers_{}", 5), format!("arithmetic sum lo")),
                    (format!("vers_{}", 6), format!("arithmetic carry hi")),
                    (format!("vers_{}", 7), format!("arithmetic carry lo")),
                ]);
            }
            arithmetic::Tag::Sub => {
                self.comments.extend([
                    (format!("vers_{}", 4), format!("arithmetic difference hi")),
                    (format!("vers_{}", 5), format!("arithmetic difference lo")),
                    (format!("vers_{}", 6), format!("arithmetic carry hi")),
                    (format!("vers_{}", 7), format!("arithmetic carry lo")),
                ]);
            }
            _ => (),
        };
    }

    // insert_public_lookup insert public lookup ,6 columns in row prev(-2)
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub fn insert_public_lookup(&mut self, public_row: &public::Row) {
        assert_eq!(self.cnt, 2.into());
        let cells = vec![
            (&mut self.vers_26, Some((public_row.tag as u8).into())),
            (&mut self.vers_27, public_row.tx_idx_or_number_diff),
            (
                &mut self.vers_28,
                Some(public_row.value_0.unwrap_or_default()),
            ),
            (
                &mut self.vers_29,
                Some(public_row.value_1.unwrap_or_default()),
            ),
            (
                &mut self.vers_30,
                Some(public_row.value_2.unwrap_or_default()),
            ),
            (
                &mut self.vers_31,
                Some(public_row.value_3.unwrap_or_default()),
            ),
        ];
        for (cell, value) in cells {
            assert!(cell.is_none());
            *cell = value;
        }
        let comments = vec![
            (format!("vers_{}", 26), format!("tag={:?}", public_row.tag)),
            (format!("vers_{}", 27), format!("tx_idx_or_number_diff")),
            (format!("vers_{}", 28), format!("value_0")),
            (format!("vers_{}", 29), format!("value_1")),
            (format!("vers_{}", 30), format!("value_2")),
            (format!("vers_{}", 31), format!("value_3")),
        ];
        self.comments.extend(comments);
    }

    pub fn insert_copy_lookup(&mut self, copy: &copy::Row, padding_copy: Option<&copy::Row>) {
        //
        assert_eq!(self.cnt, 2.into());
        let mut cells = vec![
            // code copy
            (&mut self.vers_0, (copy.src_type as u8).into()),
            (&mut self.vers_1, copy.src_id),
            (&mut self.vers_2, copy.src_pointer),
            (&mut self.vers_3, copy.src_stamp),
            (&mut self.vers_4, (copy.dst_type as u8).into()),
            (&mut self.vers_5, copy.dst_id),
            (&mut self.vers_6, copy.dst_pointer),
            (&mut self.vers_7, copy.dst_stamp),
            (&mut self.vers_8, copy.cnt),
            (&mut self.vers_9, copy.len),
            (&mut self.vers_10, copy.acc),
        ];
        let mut comments = vec![
            // copy comment
            (
                format!("vers_{}", 0),
                format!("src_type={:?}", copy.src_type),
            ),
            (format!("vers_{}", 1), format!("src_id")),
            (format!("vers_{}", 2), format!("src_pointer")),
            (format!("vers_{}", 3), format!("src_stamp")),
            (
                format!("vers_{}", 4),
                format!("dst_type={:?}", copy.dst_type),
            ),
            (format!("vers_{}", 5), format!("dst_id")),
            (format!("vers_{}", 6), format!("dst_pointer")),
            (format!("vers_{}", 7), format!("dst_stamp")),
            (format!("vers_{}", 8), format!("cnt")),
            (format!("vers_{}", 9), format!("len")),
            (format!("vers_{}", 10), format!("acc")),
        ];
        match padding_copy {
            Some(padding_copy_new) => {
                cells.extend([
                    // padding copy
                    (&mut self.vers_11, (padding_copy_new.src_type as u8).into()),
                    (&mut self.vers_12, padding_copy_new.src_id),
                    (&mut self.vers_13, padding_copy_new.src_pointer),
                    (&mut self.vers_14, padding_copy_new.src_stamp),
                    (&mut self.vers_15, (padding_copy_new.dst_type as u8).into()),
                    (&mut self.vers_16, padding_copy_new.dst_id),
                    (&mut self.vers_17, padding_copy_new.dst_pointer),
                    (&mut self.vers_18, padding_copy_new.dst_stamp),
                    (&mut self.vers_19, padding_copy_new.cnt),
                    (&mut self.vers_20, padding_copy_new.len),
                    (&mut self.vers_21, padding_copy_new.acc),
                ]);
                comments.extend([
                    // padding copy comment
                    (
                        format!("vers_{}", 11),
                        format!("padding_src_type={:?}", padding_copy_new.src_type),
                    ),
                    (format!("vers_{}", 12), format!("padding_src_id")),
                    (format!("vers_{}", 13), format!("padding_src_pointer")),
                    (format!("vers_{}", 14), format!("padding_src_stamp")),
                    (
                        format!("vers_{}", 15),
                        format!("padding_dst_type={:?}", padding_copy_new.dst_type),
                    ),
                    (format!("vers_{}", 16), format!("padding_dst_id")),
                    (format!("vers_{}", 17), format!("padding_dst_pointer")),
                    (format!("vers_{}", 18), format!("padding_dst_stamp")),
                    (format!("vers_{}", 19), format!("padding_cnt")),
                    (format!("vers_{}", 20), format!("padding_len")),
                    (format!("vers_{}", 21), format!("padding_acc")),
                ]);
            }
            None => (),
        }
        for (cell, value) in cells {
            assign_or_panic!(*cell, value);
        }
        self.comments.extend(comments);
    }

    pub fn insert_log_left_selector(&mut self, log_left: usize) {
        assert_eq!(self.cnt, 1.into());
        simple_selector_assign(
            [
                &mut self.vers_12, // LOG_LEFT_0
                &mut self.vers_11, // LOG_LEFT_1
                &mut self.vers_10, // LOG_LEFT_2
                &mut self.vers_9,  // LOG_LEFT_3
                &mut self.vers_8,  // LOG_LEFT_4
            ],
            log_left, // if log_left is X, then the location for LOG_LEFT_X is assigned by 1
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
    }

    fn gen_bytecode_witness(addr: U256, machine_code: &[u8]) -> Vec<bytecode::Row> {
        let mut res = vec![];
        let mut pc = 0;
        while pc < machine_code.len() {
            let op = OpcodeId::from(machine_code[pc]);
            let mut this_op = vec![];
            if op.is_push() {
                let mut cnt = op.as_u64() - OpcodeId::PUSH1.as_u64() + 1;
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
                    ..Default::default()
                });
                pc += 1;
                while cnt > 0 {
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
                    ..Default::default()
                });
                pc += 1;
            }
            res.append(&mut this_op);
        }
        res
    }

    /// Generate witness of block related data, such as bytecode and public table
    fn insert_block_related(&mut self, geth_data: &GethData) {
        self.public
            .append(&mut public::Row::from_geth_data(&geth_data).unwrap());
        for account in &geth_data.accounts {
            if !account.code.is_empty() {
                let mut bytcode_table =
                    Self::gen_bytecode_witness(account.address, account.code.as_ref());
                self.bytecode.append(&mut bytcode_table);
            }
        }
    }

    /// Generate begin padding of a witness of one block
    fn insert_begin_padding(&mut self) {
        // padding zero in the front
        (0..CoreCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows().0)
            .for_each(|_| self.core.insert(0, Default::default()));
        (0..BytecodeCircuit::<Fr, MAX_NUM_ROW, MAX_CODESIZE>::unusable_rows().0)
            .for_each(|_| self.bytecode.insert(0, Default::default()));
        (0..StateCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.state.insert(0, Default::default()));
        (0..CopyCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.copy.insert(0, Default::default()));
        (0..BitwiseCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.bitwise.insert(0, Default::default()));
    }

    /// Generate end padding of a witness of one block
    fn insert_end_padding(
        &mut self,
        last_step: &GethExecStep,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        // padding: add END_BLOCK to the end of core and (END_PADDING will be assigned automatically)
        let end_block_gadget = execution_gadgets_map
            .get(&ExecutionState::END_BLOCK)
            .unwrap();
        self.append(end_block_gadget.gen_witness(last_step, current_state));
    }

    fn insert_begin_block(&mut self, current_state: &mut WitnessExecHelper) {
        let begin_block: Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> =
            crate::execution::begin_block::new();
        self.append(begin_block.gen_witness(
            &GethExecStep {
                pc: 0,
                op: OpcodeId::default(),
                gas: 0,
                gas_cost: 0,
                refund: 0,
                depth: 0,
                error: None,
                stack: Stack::new(),
                memory: Memory::new(),
                storage: Storage::empty(),
            },
            current_state,
        ));
    }

    /// Generate witness of one transaction's trace
    pub fn new(geth_data: &GethData) -> Self {
        let execution_gadgets: Vec<
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        > = get_every_execution_gadgets!();
        let execution_gadgets_map = execution_gadgets
            .into_iter()
            .map(|gadget| (gadget.execution_state(), gadget))
            .collect();
        let mut witness = Witness::default();
        // step 1: insert block related witness: bytecode and public
        witness.insert_block_related(&geth_data);
        // step 2: insert padding to core, bytecode, state
        witness.insert_begin_padding();
        // step 3: create witness trace by trace, and append them
        let mut current_state = WitnessExecHelper::new();
        witness.insert_begin_block(&mut current_state);
        for (i, trace) in geth_data.geth_traces.iter().enumerate() {
            let trace_related_witness =
                current_state.generate_trace_witness(geth_data, i, &execution_gadgets_map);
            witness.append(trace_related_witness);
        }
        // step 4: insert end padding (END_BLOCK)
        witness.insert_end_padding(
            geth_data
                .geth_traces
                .last()
                .unwrap()
                .struct_logs
                .last()
                .unwrap(),
            &mut current_state,
            &execution_gadgets_map,
        );

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
            wtr.serialize((core, state, bytecode, public, arithmetic, copy, bitwise))
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
                .write(csv2html::row(&vec, i_row == 0, "".to_string(), &col_attrs).as_ref())
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
        #[rustfmt::skip]
            let vec = [
            &mut row.vers_0, &mut row.vers_1, &mut row.vers_2, &mut row.vers_3, &mut row.vers_4,
            &mut row.vers_5, &mut row.vers_6, &mut row.vers_7, &mut row.vers_8, &mut row.vers_9,
            &mut row.vers_10, &mut row.vers_11, &mut row.vers_12, &mut row.vers_13, &mut row.vers_14,
            &mut row.vers_15, &mut row.vers_16, &mut row.vers_17, &mut row.vers_18, &mut row.vers_19,
            &mut row.vers_20, &mut row.vers_21, &mut row.vers_22, &mut row.vers_23, &mut row.vers_24,
            &mut row.vers_25, &mut row.vers_26, &mut row.vers_27, &mut row.vers_28, &mut row.vers_29,
            &mut row.vers_30, &mut row.vers_31,
        ];
        for (cell, value) in vec
            .into_iter()
            .zip(selector_hi.into_iter().chain(selector_lo).chain([
                current_state.state_stamp,
                current_state.stack_pointer as u64,
                current_state.log_stamp,
                trace.gas,
                trace.refund,
                current_state.memory_chunk,
                current_state.read_only,
            ]))
        {
            *cell = Some(value.into());
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
    use super::*;
    use crate::util::geth_data_test;

    #[test]
    fn test_data_print_csv() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        witness.print_csv();
    }
}
