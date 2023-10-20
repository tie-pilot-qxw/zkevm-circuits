pub mod arithmetic;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fix;
pub mod public;
pub mod state;

use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{
    DESCRIPTION_AUXILIARY, MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
};
use crate::core_circuit::CoreCircuit;
use crate::execution::not::NotGadget;
use crate::execution::{
    get_every_execution_gadgets, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::state_circuit::StateCircuit;
use crate::util::{create_contract_addr_with_prefix, SubCircuit};
use eth_types::evm_types::{Memory, OpcodeId};
use eth_types::evm_types::{Stack, Storage};
use eth_types::geth_types::GethData;
use eth_types::U256;
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use trace_parser::Trace;

#[derive(Debug, Default, Clone)]
pub struct Witness {
    pub bytecode: Vec<bytecode::Row>,
    pub copy: Vec<copy::Row>,
    pub core: Vec<core::Row>,
    pub exp: Vec<exp::Row>,
    pub public: Vec<public::Row>,
    pub state: Vec<state::Row>,
    pub arithmetic: Vec<arithmetic::Row>,
}

pub struct CurrentState {
    pub stack: Stack,
    pub memory: Memory,
    pub storage: Storage,
    pub call_data: HashMap<u64, Vec<u8>>,
    pub value: HashMap<u64, U256>,
    pub sender: HashMap<u64, U256>,
    pub tx_idx: usize,
    pub call_id: u64,
    pub code_addr: U256,
    pub pc: u64,
    pub opcode: OpcodeId,
    pub state_stamp: u64,
    pub log_stamp: u64,
    pub gas_left: u64,
    pub refund: u64,
    pub memory_chunk: u64,
    pub read_only: u64,
    pub machine_code: Vec<u8>,
}

impl CurrentState {
    pub fn new() -> Self {
        Self {
            stack: Stack::new(),
            memory: Memory::new(),
            storage: Storage::new(HashMap::new()),
            call_data: HashMap::new(),
            value: HashMap::new(),
            sender: HashMap::new(),
            tx_idx: 0,
            call_id: 0,
            code_addr: 0.into(),
            pc: 0,
            opcode: OpcodeId::default(),
            state_stamp: 0,
            log_stamp: 0,
            gas_left: 0,
            refund: 0,
            memory_chunk: 0,
            read_only: 0,
            machine_code: vec![],
        }
    }

    pub fn copy_from_trace(&mut self, trace: &Trace) {
        self.opcode = trace.op;
        self.pc = trace.pc;
    }

    /// Generate witness of one transaction's trace
    fn generate_trace_witness(
        &mut self,
        trace: &Vec<Trace>,
        geth_data: &GethData,
        tx_idx: usize,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) -> Witness {
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
        // get bytecode: if contract-create tx, input; else find the account.code
        let bytecode = geth_data
            .accounts
            .iter()
            .filter_map(|account| {
                if account.address == to {
                    Some(account.code.to_vec())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_default();
        // add calldata to current_state
        if tx.to.is_some() {
            self.call_data.insert(call_id, tx.input.to_vec());
        }
        self.value.insert(call_id, tx.value);
        self.sender.insert(call_id, tx.from.as_bytes().into());
        self.code_addr = to;
        self.machine_code = bytecode;

        let mut res: Witness = Default::default();
        let first_trace = trace.first().unwrap(); // not actually used in BEGIN_TX_1 and BEGIN_TX_2
        self.copy_from_trace(first_trace);
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_1)
                .unwrap()
                .gen_witness(first_trace, self),
        );
        res.append(
            execution_gadgets_map
                .get(&ExecutionState::BEGIN_TX_2)
                .unwrap()
                .gen_witness(first_trace, self),
        );
        for t in trace {
            self.copy_from_trace(t);
            #[cfg(feature = "check_stack")]
            if let Some(stack) = &t.stack_for_test {
                assert_eq!(
                    stack, &self.stack.0,
                    "stack in trace mismatch with current state in trace at pc {}",
                    t.pc
                );
            }
            res.append(self.generate_execution_witness(t, &execution_gadgets_map))
        }
        res
    }

    fn generate_execution_witness(
        &mut self,
        trace: &Trace,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) -> Witness {
        let mut res = Witness::default();
        let execution_states = ExecutionState::from_opcode(trace.op);
        for execution_state in execution_states {
            if let Some(gadget) = execution_gadgets_map.get(&execution_state) {
                res.append(gadget.gen_witness(trace, self));
            } else {
                panic!("execution state {:?} not supported yet", execution_state);
            }
        }
        res
    }

    pub fn get_core_row_without_versatile(&self, multi_row_cnt: usize) -> core::Row {
        core::Row {
            tx_idx: self.tx_idx.into(),
            call_id: self.call_id.into(),
            code_addr: self.code_addr,
            pc: self.pc.into(),
            opcode: self.opcode,
            cnt: multi_row_cnt.into(),
            ..Default::default()
        }
    }

    pub fn get_pop_stack_row_value(&mut self) -> (state::Row, U256) {
        let value = self
            .stack
            .0
            .pop()
            .expect("error in current_state.get_pop_stack_row");
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack.0.len() + 1).into()), // stack pointer starts with 1, and we already pop, so +1
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, value)
    }

    pub fn get_peek_stack_row_value(&mut self, index_start_at_1: usize) -> (state::Row, U256) {
        let value = self
            .stack
            .0
            .get(self.stack.0.len() - index_start_at_1)
            .expect("error in current_state.get_peek_stack_row_value");
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack.0.len() - index_start_at_1 + 1).into()), // stack pointer starts with 1, and we already pop, so +1
            is_write: Some(0.into()),
        };
        self.state_stamp += 1;
        (res, *value)
    }

    pub fn get_memory_read_row(&mut self, dst: usize) -> state::Row {
        let value = self
            .memory
            .0
            .get(dst)
            .map(|x| x.clone())
            .unwrap_or_default();
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
        if self.memory.len() - 1 < dst {
            self.memory.extend_at_least(dst + 1);
        }
        self.memory[dst] = value;
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

    pub fn get_storage_read_row(&mut self, key: U256, contract_addr: U256) -> state::Row {
        let value = self
            .storage
            .0
            .get(&key)
            .map(|x| x.clone())
            .unwrap_or_default();
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
        res
    }

    pub fn get_storage_write_row(
        &mut self,
        key: U256,
        value: U256,
        contract_addr: U256,
    ) -> state::Row {
        self.storage.0.insert(key, value);
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

    pub fn get_push_stack_row(&mut self, value: U256) -> state::Row {
        self.stack.0.push(value);
        assert!(
            self.stack.0.len() <= 1024,
            "error in current_state.get_push_stack_row_value"
        );
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack.0.len()).into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_overwrite_stack_row(&mut self, index_start_at_1: usize, value: U256) -> state::Row {
        let len = self.stack.0.len();
        let value_in_stack = self
            .stack
            .0
            .get_mut(len - index_start_at_1)
            .expect("error in current_state.get_overwrite_stack_row");
        *value_in_stack = value;
        let res = state::Row {
            tag: Some(state::Tag::Stack),
            stamp: Some((self.state_stamp).into()),
            value_hi: Some((value >> 128).as_u128().into()),
            value_lo: Some(value.low_u128().into()),
            call_id_contract_addr: Some(self.call_id.into()),
            pointer_hi: None,
            pointer_lo: Some((self.stack.0.len() - index_start_at_1).into()),
            is_write: Some(1.into()),
        };
        self.state_stamp += 1;
        res
    }

    pub fn get_code_copy_rows(
        &mut self,
        dst: usize,
        src: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        for i in 0..len {
            let code = &self.machine_code;
            let byte = code.get(src + i).map(|x| x.clone()).unwrap();
            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Type::Bytecode,
                src_id: self.code_addr,
                src_pointer: (src + i).into(),
                src_stamp: None,
                dst_type: copy::Type::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: (dst + i).into(),
                dst_stamp: self.state_stamp.into(),
                cnt: i.into(),
                len: len.into(),
            });
            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }
        (copy_rows, state_rows)
    }

    pub fn get_calldata_copy_rows(
        &mut self,
        dst: usize,
        src: usize,
        len: usize,
    ) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        for i in 0..len {
            let call_data = &self.call_data[&self.call_id];
            let byte = call_data.get(src + i).map(|x| x.clone()).unwrap();
            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Type::Calldata,
                src_id: self.call_id.into(),
                src_pointer: (src + i).into(),
                src_stamp: Some(self.state_stamp.into()),
                dst_type: copy::Type::Memory,
                dst_id: self.call_id.into(),
                dst_pointer: (dst + i).into(),
                dst_stamp: (self.state_stamp + 1).into(),
                cnt: i.into(),
                len: len.into(),
            });
            state_rows.push(state::Row {
                tag: Some(state::Tag::CallData),
                stamp: Some(self.state_stamp.into()),
                value_hi: None,
                value_lo: Some(byte.into()),
                call_id_contract_addr: Some(self.call_id.into()),
                pointer_hi: None,
                pointer_lo: Some((src + i).into()),
                is_write: Some(0.into()),
            });
            self.state_stamp += 1;
            state_rows.push(self.get_memory_write_row(dst + i, byte));
        }

        (copy_rows, state_rows)
    }

    /// Load calldata from public table to state table
    pub fn get_load_calldata_copy_rows(&mut self) -> (Vec<copy::Row>, Vec<state::Row>) {
        let mut copy_rows = vec![];
        let mut state_rows = vec![];
        let calldata = &self.call_data[&self.call_id];
        let len = calldata.len();
        let stamp_start = self.state_stamp;
        for (i, &byte) in calldata.iter().enumerate() {
            copy_rows.push(copy::Row {
                byte: byte.into(),
                src_type: copy::Type::PublicCalldata,
                src_id: self.tx_idx.into(),
                src_pointer: 0.into(),
                src_stamp: None,
                dst_type: copy::Type::Calldata,
                dst_id: self.call_id.into(),
                dst_pointer: 0.into(),
                dst_stamp: stamp_start.into(),
                cnt: i.into(),
                len: len.into(),
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
        assert_eq!(base.pow(index), power);
        assign_or_panic!(self.vers_26, base >> 128);
        assign_or_panic!(self.vers_27, base.low_u128().into());
        assign_or_panic!(self.vers_28, index >> 128);
        assign_or_panic!(self.vers_29, index.low_u128().into());
        assign_or_panic!(self.vers_30, power >> 128);
        assign_or_panic!(self.vers_31, power.low_u128().into());
    }

    pub fn fill_versatile_with_values(&mut self, values: &[U256]) {
        #[rustfmt::skip]
            let rows = [
            &mut self.vers_0, &mut self.vers_1, &mut self.vers_2, &mut self.vers_3, &mut self.vers_4, &mut self.vers_5, &mut self.vers_6, &mut self.vers_7,
            &mut self.vers_8, &mut self.vers_9, &mut self.vers_10, &mut self.vers_11, &mut self.vers_12, &mut self.vers_13, &mut self.vers_14, &mut self.vers_15,
            &mut self.vers_16, &mut self.vers_17, &mut self.vers_18, &mut self.vers_19, &mut self.vers_20, &mut self.vers_21, &mut self.vers_22, &mut self.vers_23,
            &mut self.vers_24, &mut self.vers_25, &mut self.vers_26, &mut self.vers_27, &mut self.vers_28, &mut self.vers_29, &mut self.vers_30, &mut self.vers_31
        ];
        for (row, v) in rows.into_iter().zip(values) {
            *row = Some(v.clone());
        }
    }

    pub fn insert_bitwise_op_tag(&mut self, tag: usize) {
        assign_or_panic!(self.vers_25, tag.into());
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

    pub fn insert_bytecode_full_lookup(
        &mut self,
        pc: u64,
        opcode: OpcodeId,
        push_value: Option<U256>,
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());

        for (own, value) in [
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
            Some(self.code_addr),
            Some(pc.into()),
            Some(opcode.as_u8().into()),
            Some(0.into()), // non_code must be 0
            push_value.map(|x| (x >> 128).as_u128().into()),
            push_value.map(|x| (x.low_u128().into())),
            Some(opcode.data_len().into()),
            Some((opcode.is_push() as u8).into()),
        ]) {
            // before inserting, these columns must be none
            assert!(own.is_none());
            *own = value;
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

    pub fn insert_arithmetic_lookup(&mut self, arithmetic: &arithmetic::Row) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 2.into());
        assert_eq!(arithmetic.cnt, Some(0.into()));

        for (own, value) in [
            (&mut self.vers_0, arithmetic.operand0_hi),
            (&mut self.vers_1, arithmetic.operand0_lo),
            (&mut self.vers_2, arithmetic.operand1_hi),
            (&mut self.vers_3, arithmetic.operand1_lo),
            (&mut self.vers_4, arithmetic.operand2_hi),
            (&mut self.vers_5, arithmetic.operand2_lo),
            (&mut self.vers_6, arithmetic.operand3_hi),
            (&mut self.vers_7, arithmetic.operand3_lo),
            (
                &mut self.vers_8,
                arithmetic.tag.map(|tag| (tag as u8).into()),
            ),
        ] {
            // before inserting, these columns must be none
            assert!(own.is_none());
            *own = value;
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", 8), format!("{:?}", arithmetic.tag)),
        ]);
    }

    pub fn insert_copy_lookup(&mut self, copy: &copy::Row) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 2.into());

        for (own, value) in [
            (&mut self.vers_0, Some((copy.src_type as u8).into())),
            (&mut self.vers_1, Some(copy.src_id)),
            (&mut self.vers_2, Some(copy.src_pointer)),
            (&mut self.vers_3, copy.src_stamp),
            (&mut self.vers_4, Some((copy.dst_type as u8).into())),
            (&mut self.vers_5, Some(copy.dst_id)),
            (&mut self.vers_6, Some(copy.dst_pointer)),
            (&mut self.vers_7, Some(copy.dst_stamp)),
            (&mut self.vers_8, Some(copy.len)),
        ] {
            // before inserting, these columns must be none
            assert!(own.is_none());
            *own = value;
        }
        #[rustfmt::skip]
        self.comments.extend([
            (format!("vers_{}", 0), format!("src_type={:?}", copy.src_type)),
            (format!("vers_{}", 1), format!("src_id")),
            (format!("vers_{}", 2), format!("src_pointer")),
            (format!("vers_{}", 3), format!("src_stamp")),
            (format!("vers_{}", 4), format!("dst_type={:?}", copy.dst_type)),
            (format!("vers_{}", 5), format!("dst_id")),
            (format!("vers_{}", 6), format!("dst_pointer")),
            (format!("vers_{}", 7), format!("dst_stamp")),
            (format!("vers_{}", 8), format!("len")),
            (format!("vers_{}", 9), format!("push_value_lo")),
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

    pub fn gen_arithmetic_witness(
        tag: arithmetic::Tag,
        operands: [U256; 4],
    ) -> Vec<arithmetic::Row> {
        let mut row_0 = arithmetic::Row {
            tag: Some(tag),
            cnt: Some(0.into()),
            ..Default::default()
        };
        for (operand, (hi, lo)) in operands.into_iter().zip([
            (&mut row_0.operand0_hi, &mut row_0.operand0_lo),
            (&mut row_0.operand1_hi, &mut row_0.operand1_lo),
            (&mut row_0.operand2_hi, &mut row_0.operand2_lo),
            (&mut row_0.operand3_hi, &mut row_0.operand3_lo),
        ]) {
            *hi = Some((operand >> 128).as_u128().into());
            *lo = Some(operand.low_u128().into());
        }
        // todo generate more rows
        vec![row_0]
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
    }

    /// Generate end padding of a witness of one block
    fn insert_end_padding(
        &mut self,
        last_trace: &Trace,
        current_state: &mut CurrentState,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        // padding: add END_BLOCK to the end of core and (END_PADDING will be assigned automatically)
        let end_block_gadget = execution_gadgets_map
            .get(&ExecutionState::END_BLOCK)
            .unwrap();
        self.append(end_block_gadget.gen_witness(last_trace, current_state));
    }

    /// Generate witness of one transaction's trace
    pub fn new(trace: &Vec<Vec<Trace>>, geth_data: &GethData) -> Self {
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
        let mut current_state = CurrentState::new();
        for (i, trace) in trace.iter().enumerate() {
            let trace_related_witness =
                current_state.generate_trace_witness(trace, geth_data, i, &execution_gadgets_map);
            witness.append(trace_related_witness);
        }
        // step 4: insert end padding (END_BLOCK)
        witness.insert_end_padding(
            trace.last().unwrap().last().unwrap(),
            &mut current_state,
            &execution_gadgets_map,
        );
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
        ])
        .unwrap();
        for i in 0..max_length {
            let core = self.core.get(i).map(|x| x.clone()).unwrap_or_default();
            let state = self.state.get(i).map(|x| x.clone()).unwrap_or_default();
            let bytecode = self.bytecode.get(i).map(|x| x.clone()).unwrap_or_default();
            let public = self.public.get(i).map(|x| x.clone()).unwrap_or_default();
            let arithmetic = self
                .arithmetic
                .get(i)
                .map(|x| x.clone())
                .unwrap_or_default();
            wtr.serialize((core, state, bytecode, public, arithmetic))
                .unwrap()
        }
        wtr.flush().unwrap();
    }

    pub fn write_one_as_csv<W: Write, T: Serialize>(&self, writer: W, table: &Vec<T>) {
        let mut wtr = csv::Writer::from_writer(writer);
        table.iter().for_each(|row| {
            wtr.serialize(row).unwrap();
        });
        wtr.flush().unwrap();
    }

    pub fn print_csv(&self) {
        self.write_all_as_csv(std::io::stdout());
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
        self.write_one_as_csv(&mut buf, table);
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
        self.write_one_table(&mut writer, &self.public, "Public", None);
        self.write_one_table(&mut writer, &self.copy, "Copy", None);
        self.write_one_table(&mut writer, &self.exp, "Exp", None);
        self.write_one_table(&mut writer, &self.arithmetic, "Arithmetic", None);
        writer.write(csv2html::epilogue().as_ref()).unwrap();
    }
}

impl ExecutionState {
    pub fn into_exec_state_core_row(
        self,
        current_state: &CurrentState,
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
        let mut row = current_state.get_core_row_without_versatile(0);
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
                current_state.stack.0.len() as u64,
                current_state.log_stamp,
                current_state.gas_left,
                current_state.refund,
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
        let trace = trace_parser::trace_program(&machine_code);
        let witness = Witness::new(&vec![trace], &geth_data_test(&machine_code, &[], false));
        witness.print_csv();
    }
}
