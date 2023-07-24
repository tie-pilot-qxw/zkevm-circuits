pub mod arithmetic;
pub(crate) mod block;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fix;
pub mod public;
pub mod state;

use crate::execution;
use crate::execution::ExecutionGadget;
pub use block::Block;
pub use block::{EXECUTION_STATE_NUM, OPERAND_NUM};
use eth_types::evm_types::OpcodeId;
use eth_types::evm_types::Stack;
use eth_types::U256;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::ff::PrimeField;
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
    /// the number of padding in advice columns at the beginning
    pub num_padding_begin: usize,
    /// the number of padding in advice columns in the end
    pub num_padding_end: usize,
    /// the max codesize to do permutation constraint in bytecode circuit
    pub max_codesize: usize,
    /// the number of rows including padding after witness; <= 2^k
    pub num_row_incl_padding: usize,
}

pub struct CurrentState {
    pub stack: Stack,
    pub memory: HashMap<u64, u8>,
    pub storage: HashMap<u128, u8>,
    pub tx_idx: u64,
    pub call_id: u64,
    pub code_addr: u64,
    pub stamp_count: u64,
}

impl Witness {
    fn get_next_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness {
        match trace.op {
            OpcodeId::ADD => execution::add::AddGadget::<Fr>::gen_witness(trace, current_state),
            OpcodeId::PUSH1 => execution::push::PushGadget::<Fr>::gen_witness(trace, current_state),
            OpcodeId::PUSH30 => {
                execution::push::PushGadget::<Fr>::gen_witness(trace, current_state)
            }
            OpcodeId::STOP => execution::stop::StopGadget::<Fr>::gen_witness(trace, current_state),
            a => panic!("{}", a.to_string()),
        }
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

    pub fn new(trace: &Vec<Trace>, machine_code: &Vec<u8>) -> Self {
        let mut res = Witness {
            bytecode: Self::gen_bytecode_witness(0.into(), machine_code),
            ..Default::default()
        }; // todo: padding zero in the front
        let mut current_state = CurrentState {
            stack: Stack::new(),
            memory: HashMap::new(),
            storage: HashMap::new(),
            tx_idx: 0,
            call_id: 0,
            code_addr: 0,
            stamp_count: 0,
        };
        for t in trace {
            res.append(Self::get_next_witness(&t, &mut current_state))
        }
        res
    }

    pub fn print_csv(&self) {
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        let max_length = max(
            max(self.core.len(), self.bytecode.len()),
            max(self.state.len(), self.arithmetic.len()),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness_table = Witness::new(&trace, &machine_code);
        witness_table.print_csv();
    }
}
