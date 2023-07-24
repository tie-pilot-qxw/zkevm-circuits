pub mod arithmetic;
pub(crate) mod block;
pub mod bytecode;
pub mod copy;
pub mod core;
pub mod exp;
pub mod fix;
pub mod public;
pub mod state;

pub use block::Block;
pub use block::{EXECUTION_STATE_NUM, OPERAND_NUM};
use eth_types::evm_types::OpcodeId;
use eth_types::evm_types::Stack;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::ff::PrimeField;
use std::cmp::max;
use std::collections::HashMap;
use trace_parser::Trace;

use crate::execution;
use crate::execution::ExecutionGadget;

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

    pub fn new(trace: &Vec<Trace>) -> Self {
        let mut res = Witness {
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
            self.core.len(),
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
            wtr.serialize((core, state, arithmetic)).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let machine_code = trace_parser::assemble_file("debug/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness_table = Witness::new(&trace);
        witness_table.print_csv();
    }
}
