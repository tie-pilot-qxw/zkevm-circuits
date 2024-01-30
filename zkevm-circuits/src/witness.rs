pub mod arithmetic;
pub mod bitwise;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fixed;
pub mod public;
pub mod state;

use crate::arithmetic_circuit::{operation, ArithmeticCircuit};
use crate::bitwise_circuit::BitwiseCircuit;
use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{
    BIT_SHIFT_MAX_INDEX, COPY_LOOKUP_COLUMN_CNT, DESCRIPTION_AUXILIARY, MAX_CODESIZE, MAX_NUM_ROW,
    NUM_STATE_HI_COL, NUM_STATE_LO_COL, NUM_VERS, PUBLIC_NUM_VALUES,
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
use crate::witness::public::{public_rows_to_instance, LogTag};
use crate::witness::state::{CallContextTag, Tag};
use eth_types::evm_types::{Memory, OpcodeId, Stack, Storage};
use eth_types::geth_types::GethData;
use eth_types::{Bytecode, Field, GethExecStep, U256};
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use gadgets::simple_seletor::simple_selector_assign;
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
    pub tx_num_in_block: usize,
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
    // used to temporarily store the results of sar1 calculations for use by sar2 (shr result and sign bit)
    pub sar: Option<(U256, U256)>,
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
            tx_num_in_block: 0,
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
            sar: None,
            tx_value: 0.into(),
            parent_pc: HashMap::new(),
        }
    }

    pub fn update_from_next_step(&mut self, trace: &GethExecStep) {
        self.stack_top = trace.stack.0.last().cloned();
    }

    /// stack_pointer decrease
    pub fn stack_pointer_decrease(&mut self) {
        self.stack_pointer -= 1;
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

        self.value.insert(call_id, tx.value);
        self.tx_value = tx.value;
        self.sender.insert(call_id, tx.from.as_bytes().into());
        self.code_addr = to;
        self.storage_contract_addr.insert(call_id, to);
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

        let mut prev_is_return_revert_or_stop = false;
        let mut call_step_store: Vec<&GethExecStep> = vec![];
        for step in trace {
            if let Some(next_step) = iter_for_next_step.next() {
                self.update_from_next_step(next_step);
            }

            if prev_is_return_revert_or_stop {
                // append CALL5 when the previous opcode is RETURN, REVERT or STOP which indicates the end of the lower-level call (this doesn't append CALL5 at the end of the top-level call, because the total for-loop has ended)
                let call_trace_step = call_step_store.pop().unwrap();
                res.append(
                    execution_gadgets_map
                        .get(&ExecutionState::CALL_5)
                        .unwrap()
                        .gen_witness(call_trace_step, self),
                );
                prev_is_return_revert_or_stop = false;
            }
            res.append(self.generate_execution_witness(step, &execution_gadgets_map));

            match step.op {
                OpcodeId::RETURN | OpcodeId::REVERT | OpcodeId::STOP => {
                    prev_is_return_revert_or_stop = true;
                }
                OpcodeId::CALL => {
                    call_step_store.push(step);
                }
                _ => {}
            }
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
            tag: Some(Tag::Stack),
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
            tag: Some(Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack_pointer + 1 - index_start_at_1).into()), // stack pointer start at 1, hence +1
            is_write: Some(0.into()),
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
            tag: Some(Tag::Stack),
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
        let src_offset = if uint64_with_overflow(&src) {
            u64::MAX
        } else {
            // it's guaranteed by caller that it is in range u64
            src.as_u64()
        };
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
                    acc,
                });
                // it's guaranteed by Ethereum that dst + i doesn't overflow, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L31
                state_rows.push(self.get_memory_write_row(dst + i, byte));
            }
        }
        let codecopy_padding_stamp = self.state_stamp;
        if padding_length > 0 {
            for i in 0..padding_length {
                state_rows.push(self.get_memory_write_row(
                    // in the same way, dst + code_copy_length + i doesn't overflow
                    dst + code_copy_length + i,
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
            // it's guaranteed by Ethereum that src + i doesn't overflow, reference: https://github.com/ethereum/go-ethereum/blob/master/core/vm/memory_table.go#L67
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
                acc,
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
            tag: Some(Tag::CallContext),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((self.returndata_size >> 128).as_u128().into()),
            value_lo: Some(self.returndata_size.low_u128().into()),
            call_id_contract_addr: Some(self.returndata_call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((CallContextTag::ReturnDataSize as u8).into()),
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, self.returndata_size.into())
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
                dst_id: self.tx_idx.into(), // tx_idx
                dst_pointer: 0.into(),      // PublicLog index
                dst_stamp: log_stamp.into(),
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
        comments.insert(format!("vers_{}", 27), "tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(format!("vers_{}", 29), format!("log tag={}", "DataSize"));
        comments.insert(format!("vers_{}", 30), "0".into());
        comments.insert(format!("vers_{}", 31), "data_len".into());

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
        comments.insert(format!("vers_{}", 27), "tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(
            format!("vers_{}", 29),
            format!("topic_log_tag={}", topic_tag),
        );
        comments.insert(format!("vers_{}", 30), "topic_hash[..16]".into());
        comments.insert(format!("vers_{}", 31), "topic_hash[16..]".into());

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
        let value_hi = (self.code_addr >> 128).as_u128();
        let value_lo = self.code_addr.low_u128();

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), format!("tag={}", "TxLog"));
        comments.insert(format!("vers_{}", 27), "tx_idx".into());
        comments.insert(format!("vers_{}", 28), "log_index".into());
        comments.insert(format!("vers_{}", 29), format!("log_tag={}", log_tag_name));
        comments.insert(format!("vers_{}", 30), "address[..4]".into());
        comments.insert(format!("vers_{}", 31), "address[4..]".into());

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

    pub fn get_public_tx_row(&self, tag: public::Tag) -> public::Row {
        let values: [Option<U256>; PUBLIC_NUM_VALUES];
        let value_comments: [String; PUBLIC_NUM_VALUES];
        let mut tx_idx = self.tx_idx as u64;
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
                    "from[..4]".into(),
                    "from[4..]".into(),
                    "value[..16]".into(),
                    "value[16..]".into(),
                ]
            }
            public::Tag::BlockTxNum => {
                values = [Some(self.tx_num_in_block.into()), None, None, None];
                value_comments = ["tx_num_in_block".into(), "".into(), "".into(), "".into()];
                tx_idx = 0;
            }
            public::Tag::BlockLogNum => {
                values = [Some(self.log_stamp.into()), None, None, None];
                value_comments = ["log_num".into(), "".into(), "".into(), "".into()];
                tx_idx = 0;
            }
            _ => panic!(),
        };

        let mut comments = HashMap::new();
        comments.insert(format!("vers_{}", 26), "tag".into());
        comments.insert(format!("vers_{}", 27), "tx_idx".into());
        comments.insert(format!("vers_{}", 28), value_comments[0].clone());
        comments.insert(format!("vers_{}", 29), value_comments[1].clone());
        comments.insert(format!("vers_{}", 30), value_comments[2].clone());
        comments.insert(format!("vers_{}", 31), value_comments[3].clone());

        let public_row = public::Row {
            tag,
            tx_idx_or_number_diff: Some(U256::from(tx_idx)),
            value_0: values[0],
            value_1: values[1],
            value_2: values[2],
            value_3: values[3],
            comments,
        };

        public_row
    }
}

pub fn get_and_insert_shl_shr_rows<F: Field>(
    shift: U256,
    value: U256,
    op: OpcodeId,
    core_rows1: &mut core::Row,
    core_rows2: &mut core::Row,
) -> (Vec<arithmetic::Row>, Vec<exp::Row>) {
    // 255 - a
    // the main purpose is to determine whether shift is greater than or equal to 256
    // that is, whether 2<<shift will overflow
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![BIT_SHIFT_MAX_INDEX.into(), shift]);

    // mul_div_num = 2<<stack_shift
    let mul_div_num = if shift > BIT_SHIFT_MAX_INDEX.into() {
        0.into()
    } else {
        U256::from(1) << shift
    };

    // if Opcode is SHL, then result is stack_value * mul_div_num
    // if Opcode is SHR, then result is stack_value / mul_div_num
    let (arithmetic_mul_div_rows, _) = match op {
        OpcodeId::SHL => operation::mul::gen_witness(vec![value, mul_div_num]),
        OpcodeId::SHR => operation::div_mod::gen_witness(vec![value, mul_div_num]),
        _ => panic!("not shl or shr"),
    };

    // insert arithmetic-sub in lookup
    core_rows2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
    // insert arithmetic-mul_div in lookup
    core_rows2.insert_arithmetic_lookup(1, &arithmetic_mul_div_rows);

    // insert exp lookup
    core_rows1.insert_exp_lookup(U256::from(2), shift, mul_div_num);
    let exp_rows = exp::Row::from_operands(U256::from(2), shift, mul_div_num);

    let mut arithmetic_rows = vec![];
    arithmetic_rows.extend(arithmetic_sub_rows);
    arithmetic_rows.extend(arithmetic_mul_div_rows);

    (arithmetic_rows, exp_rows)
}

pub fn get_and_insert_signextend_rows<F: Field>(
    signextend_operands: [U256; 2],
    exp_operands: [U256; 3],
    arithmetic_operands: [U256; 2],
    core_rows0: &mut core::Row,
    core_rows1: &mut core::Row,
    core_rows2: &mut core::Row,
) -> (Vec<bitwise::Row>, Vec<exp::Row>, Vec<arithmetic::Row>) {
    // get arithmetic rows
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![arithmetic_operands[0], arithmetic_operands[1]]);
    const START_OFFSET: usize = 27;
    // get exp_rows
    let exp_rows = exp::Row::from_operands(
        exp_operands[0].clone(),
        exp_operands[1].clone(),
        exp_operands[2].clone(),
    );

    // calc signextend by bit
    let (signextend_result_vec, bitwise_rows_vec) =
        signextend_by_bit::<F>(signextend_operands[0], signextend_operands[1]);

    // insert bitwise lookup
    for (i, bitwise_lookup) in bitwise_rows_vec.iter().enumerate() {
        core_rows2.insert_bitwise_lookups(i, bitwise_lookup.last().unwrap());
    }
    // insert arithmetic lookup to core_row_2
    core_rows2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);

    // insert exp lookup
    core_rows1.insert_exp_lookup(exp_operands[0], exp_operands[1], exp_operands[2]);

    // a_hi set core_row_0.vers_27;
    // a_lo set core_row_0.vers_28;
    // d_hi set core_row_0.vers_29
    // d_lo set core_row_0.vers_30
    // sign_bit_is_zero_inv set core_row_0.vers_31;
    for (i, value) in (0..5).zip(signextend_result_vec) {
        assert!(core_rows0[i + START_OFFSET].is_none());
        assign_or_panic!(core_rows0[i + START_OFFSET], value);
    }
    // Construct Witness object
    let bitwise_rows = bitwise_rows_vec
        .into_iter()
        .flat_map(|inner_vec| inner_vec.into_iter())
        .collect();

    (bitwise_rows, exp_rows, arithmetic_sub_rows)
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
        // todo: exp overflow
        let (expect_power, _) = base.overflowing_pow(index);
        assert_eq!(expect_power, power);
        const START_OFFSET: usize = 26;
        let colum_values = [
            base >> 128,
            base.low_u128().into(),
            index >> 128,
            index.low_u128().into(),
            power >> 128,
            power.low_u128().into(),
        ];
        for i in 0..6 {
            assign_or_panic!(self[START_OFFSET + i], colum_values[i]);
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
        const START_OFFSET: usize = 10;
        const COLUMN_WIDTH: usize = 5;
        let column_values = [
            U256::from(bitwise_row.tag as u8),
            bitwise_row.acc_0,
            bitwise_row.acc_1,
            bitwise_row.acc_2,
            bitwise_row.sum_2,
        ];
        for i in 0..COLUMN_WIDTH {
            assign_or_panic!(
                self[START_OFFSET + COLUMN_WIDTH * index + i],
                column_values[i]
            );
        }
        self.comments.extend([
            (
                format!("vers_{}", index * 5),
                format!("tag:{:?}", bitwise_row.tag),
            ),
            (format!("vers_{}", index * 5 + 1), "acc_0".into()),
            (format!("vers_{}", index * 5 + 2), "acc_1".into()),
            (format!("vers_{}", index * 5 + 3), "acc_2".into()),
            (format!("vers_{}", index * 5 + 4), "sum_2".into()),
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
        const COLUMN_WIDTH: usize = 8;
        for (j, state_row) in state_rows.into_iter().enumerate() {
            for i in 0..8 {
                assert!(self[i + j * COLUMN_WIDTH].is_none());
            }
            self[0 + j * COLUMN_WIDTH] = state_row.tag.map(|tag| (tag as u8).into());
            self[1 + j * COLUMN_WIDTH] = state_row.stamp;
            self[2 + j * COLUMN_WIDTH] = state_row.value_hi;
            self[3 + j * COLUMN_WIDTH] = state_row.value_lo;
            self[4 + j * COLUMN_WIDTH] = state_row.call_id_contract_addr;
            self[5 + j * COLUMN_WIDTH] = state_row.pointer_hi;
            self[6 + j * COLUMN_WIDTH] = state_row.pointer_lo;
            self[7 + j * COLUMN_WIDTH] = state_row.is_write;
            self.comments.extend([
                (
                    format!("vers_{}", j * COLUMN_WIDTH),
                    format!("tag={:?}", state_row.tag),
                ),
                (format!("vers_{}", j * COLUMN_WIDTH + 1), "stamp".into()),
                (format!("vers_{}", j * COLUMN_WIDTH + 2), "value_hi".into()),
                (format!("vers_{}", j * COLUMN_WIDTH + 3), "value_lo".into()),
                (format!("vers_{}", j * COLUMN_WIDTH + 4), "call_id".into()),
                (format!("vers_{}", j * COLUMN_WIDTH + 5), "not used".into()),
                (
                    format!("vers_{}", j * COLUMN_WIDTH + 6),
                    "stack pointer".into(),
                ),
                (
                    format!("vers_{}", j * COLUMN_WIDTH + 7),
                    "is_write: read=0, write=1".into(),
                ),
            ]);
        }
    }

    /// insert_stamp_cnt_lookups, include tag and cnt of state, tag always be EndPadding
    pub fn insert_stamp_cnt_lookups(&mut self, cnt: U256) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        assign_or_panic!(self[0], U256::from(Tag::EndPadding as u8));
        assign_or_panic!(self[1], cnt);

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
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        const START: usize = 24;
        for (i, value) in (0..8).zip([
            Some(code_addr),
            Some(pc.into()),
            Some(opcode.as_u8().into()),
            Some(0.into()), // non_code must be 0
            push_value.map(|x| (x >> 128).as_u128().into()),
            push_value.map(|x| (x.low_u128().into())),
            Some(opcode.data_len().into()),
            Some((opcode.is_push() as u8).into()),
        ]) {
            assert!(self[START + i].is_none());
            self[START + i] = value;
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", 24), "code_addr".into()),
            (format!("vers_{}", 25), "pc".into()),
            (format!("vers_{}", 26), format!("opcode={}", opcode)),
            (format!("vers_{}", 27), "non_code must be 0".into()),
            (format!("vers_{}", 28), "push_value_hi".into()),
            (format!("vers_{}", 29), "push_value_lo".into()),
            (format!("vers_{}", 30), "X for PUSHX".into()),
            (format!("vers_{}", 31), "is_push".into()),
        ]);
    }

    pub fn insert_arithmetic_u64overflow_lookup(
        &mut self,
        index: usize,
        arith_entries: &[arithmetic::Row],
    ) {
        const _START: usize = 22;
        const WIDTH: usize = 4;
        assert_eq!(self.cnt, 2.into());
        assert_eq!(arith_entries.len(), 1);
        assert_eq!(index, 0);

        let column_values = [
            arith_entries[0].operand_0_hi,
            arith_entries[0].operand_0_lo,
            arith_entries[0].operand_1_hi,
            arith_entries[0].operand_1_lo,
        ];
        for i in 0..4 {
            assign_or_panic!(self[_START + i], column_values[i]);
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", WIDTH), "arithmetic operand 0 hi".into()),
            (format!("vers_{}", WIDTH + 1), "arithmetic operand 0 lo".into()),
            (format!("vers_{}", WIDTH + 2), "arithmetic operand 1 hi".into()),
            (format!("vers_{}", WIDTH + 3), "arithmetic operand 1 lo".into()),
        ]);
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
        const WIDTH: usize = 9;
        assert!(index < 3);
        assert_eq!(self.cnt, 2.into());
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
        let column_offset = index * WIDTH;
        for i in 0..WIDTH {
            assign_or_panic!(self[i + column_offset], column_values[i]);
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", index * WIDTH), "arithmetic operand 0 hi".into()),
            (format!("vers_{}", index * WIDTH + 1), "arithmetic operand 0 lo".into()),
            (format!("vers_{}", index * WIDTH + 2), "arithmetic operand 1 hi".into()),
            (format!("vers_{}", index * WIDTH + 3), "arithmetic operand 1 lo".into()),
            (format!("vers_{}", index * WIDTH + 8), format!("arithmetic tag={:?}", row_0.tag)),
        ]);
        match row_0.tag {
            arithmetic::Tag::Add => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * WIDTH + 4),
                        "arithmetic sum hi".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 5),
                        "arithmetic sum lo".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Addmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * WIDTH + 4),
                        format!("arithmetic operand modulus hi"),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 5),
                        format!("arithmetic operand modulus lo"),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 6),
                        format!("arithmetic remainder hi"),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 7),
                        format!("arithmetic remainder lo"),
                    ),
                ]);
            }
            arithmetic::Tag::Sub => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * WIDTH + 4),
                        "arithmetic difference hi".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 5),
                        "arithmetic difference lo".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Mulmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * WIDTH + 6),
                        format!("arithmetic r hi"),
                    ),
                    (
                        format!("vers_{}", index * WIDTH + 7),
                        format!("arithmetic r lo"),
                    ),
                ]);
            }
            arithmetic::Tag::DivMod | arithmetic::Tag::SdivSmod => self.comments.extend([
                (
                    format!("vers_{}", index * WIDTH + 4),
                    "arithmetic quotient hi".into(),
                ),
                (
                    format!("vers_{}", index * WIDTH + 5),
                    "arithmetic quotient lo".into(),
                ),
                (
                    format!("vers_{}", index * WIDTH + 6),
                    "arithmetic remainder hi".into(),
                ),
                (
                    format!("vers_{}", index * WIDTH + 7),
                    "arithmetic remainder lo".into(),
                ),
            ]),
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
        const START_OFFSET: usize = 26;
        let column_values = [
            (public_row.tag as u8).into(),
            public_row.tx_idx_or_number_diff.unwrap_or_default(),
            public_row.value_0.unwrap_or_default(),
            public_row.value_1.unwrap_or_default(),
            public_row.value_2.unwrap_or_default(),
            public_row.value_3.unwrap_or_default(),
        ];
        for i in 0..6 {
            assert!(self[i + START_OFFSET].is_none());
            assign_or_panic!(self[i + START_OFFSET], column_values[i]);
        }
        let comments = vec![
            (format!("vers_{}", 26), format!("tag={:?}", public_row.tag)),
            (format!("vers_{}", 27), "tx_idx_or_number_diff".into()),
            (format!("vers_{}", 28), "value_0".into()),
            (format!("vers_{}", 29), "value_1".into()),
            (format!("vers_{}", 30), "value_2".into()),
            (format!("vers_{}", 31), "value_3".into()),
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
                if pc + cnt as usize >= machine_code.len() {
                    break;
                } // NOTE: the purpose is to avoid the effects of invalid bytecodes, for example, a PUSH31 opcode at machine_code.len()-23
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
                let mut bytecode_table =
                    Self::gen_bytecode_witness(account.address, account.code.as_ref());
                self.bytecode.append(&mut bytecode_table);
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
        (0..ArithmeticCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.arithmetic.insert(0, Default::default()));
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
        self.append(begin_block_gadget.gen_witness(
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
        assert!(U256::from(usize::MAX) >= U256::from(u64::MAX),"struct Memory doesn't support evm's memory because the range of usize is smaller than that of u64");
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
        witness.insert_begin_block(&mut current_state, &execution_gadgets_map);
        // initialize txs number in current_state with geth_data
        current_state.tx_num_in_block = geth_data.eth_block.transactions.len();
        for i in 0..geth_data.geth_traces.len() {
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
        for (i, value) in
            (0..NUM_VERS)
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
