pub mod arithmetic;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fix;
pub mod public;
pub mod state;

use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use crate::core_circuit::CoreCircuit;
use crate::execution::{get_every_execution_gadgets, ExecutionGadget, ExecutionState};
use crate::util::SubCircuit;
use eth_types::evm_types::OpcodeId;
use eth_types::evm_types::Stack;
use eth_types::U256;
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use halo2_proofs::halo2curves::bn256::Fr;
use std::cmp::max;
use std::collections::HashMap;
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

// todo consider move to trace_parser
pub struct CurrentState {
    pub stack: Stack,
    pub memory: HashMap<u64, u8>,
    pub storage: HashMap<u128, u8>,
    pub tx_idx: u64,
    pub call_id: u64,
    pub code_addr: u64,
    pub pc: u64,
    pub opcode: OpcodeId,
    pub state_stamp: u64,
    pub log_stamp: u64,
    pub gas_left: u64,
    pub refund: u64,
    pub memory_chunk: u64,
    pub read_only: u64,
}

impl CurrentState {
    pub fn new() -> Self {
        Self {
            stack: Stack::new(),
            memory: HashMap::new(),
            storage: HashMap::new(),
            tx_idx: 0,
            call_id: 0,
            code_addr: 0,
            pc: 0,
            opcode: OpcodeId::default(),
            state_stamp: 0,
            log_stamp: 0,
            gas_left: 0,
            refund: 0,
            memory_chunk: 0,
            read_only: 0,
        }
    }

    pub fn copy_from_trace(&mut self, trace: &Trace) {
        self.opcode = trace.op;
        self.pc = trace.pc;
    }

    pub fn get_core_row_without_versatile(&self, multi_row_cnt: usize) -> core::Row {
        core::Row {
            tx_idx: self.tx_idx.into(),
            call_id: self.call_id.into(),
            code_addr: self.code_addr.into(),
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
}

impl core::Row {
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
        for (state_row, core_row) in state_rows.into_iter().zip(vec) {
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
    }
}

impl Witness {
    fn get_next_witness(
        trace: &Trace,
        current_state: &mut CurrentState,
        execution_gadget_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) -> Witness {
        let mut res = Witness::default();
        let execution_states = ExecutionState::from_opcode(trace.op);
        for execution_state in execution_states {
            if let Some(gadget) = execution_gadget_map.get(&execution_state) {
                res.append(gadget.gen_witness(trace, current_state));
            } else {
                panic!("execution state {:?} not supported yet", execution_state);
            }
        }
        res
    }

    fn append(&mut self, mut witness: Witness) {
        self.bytecode.append(&mut witness.bytecode);
        self.copy.append(&mut witness.copy);
        self.core.append(&mut witness.core);
        self.exp.append(&mut witness.exp);
        self.public.append(&mut witness.public);
        self.state.append(&mut witness.state);
        self.arithmetic.append(&mut witness.arithmetic);
    }

    fn gen_bytecode_witness(addr: U256, machine_code: &Vec<u8>) -> Vec<bytecode::Row> {
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

    pub fn new(trace: &Vec<Trace>, machine_code: &Vec<u8>) -> Self {
        let mut res = Witness {
            bytecode: Self::gen_bytecode_witness(0xff.into(), machine_code),
            ..Default::default()
        };
        let mut current_state = CurrentState {
            code_addr: 0xff, //replace with real addr
            ..CurrentState::new()
        };
        let execution_gadgets: Vec<
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        > = get_every_execution_gadgets!();
        let execution_gadgets_map = execution_gadgets
            .into_iter()
            .map(|gadget| (gadget.execution_state(), gadget))
            .collect();
        for t in trace {
            current_state.copy_from_trace(t);
            res.append(Self::get_next_witness(
                &t,
                &mut current_state,
                &execution_gadgets_map,
            ))
        }
        // add END_BLOCK to the end of core
        res.core
            .push(ExecutionState::END_BLOCK.into_exec_state_core_row(
                &mut current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            ));
        // padding zero in the front
        (0..CoreCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows().0)
            .for_each(|_| res.core.insert(0, Default::default()));
        (0..BytecodeCircuit::<Fr, MAX_NUM_ROW, MAX_CODESIZE>::unusable_rows().0)
            .for_each(|_| res.bytecode.insert(0, Default::default()));
        res
    }

    pub fn print_csv(&self) {
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        let max_length = itertools::max([
            self.core.len(),
            self.bytecode.len(),
            self.state.len(),
            self.arithmetic.len(),
        ])
        .unwrap();
        for i in 0..max_length {
            let core = self.core.get(i).map(|x| x.clone()).unwrap_or_default();
            let state = self.state.get(i).map(|x| x.clone()).unwrap_or_default();
            let arithmetic = self
                .arithmetic
                .get(i)
                .map(|x| x.clone())
                .unwrap_or_default();
            let bytecode = self.bytecode.get(i).map(|x| x.clone()).unwrap_or_default();
            wtr.serialize((core, state, arithmetic, bytecode)).unwrap()
        }
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
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_print_csv() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness_table = Witness::new(&trace, &machine_code);
        witness_table.print_csv();
    }
}
