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
use trace_parser::Trace;

pub struct Witness {
    bytecode: Vec<bytecode::Row>,
    copy: Vec<copy::Row>,
    core: Vec<core::Row>,
    exp: Vec<exp::Row>,
    public: Vec<public::Row>,
    state: Vec<state::Row>,
}

struct CurrentState {}

impl Witness {
    fn new(trace: Vec<Trace>) -> Self {
        unimplemented!()
    }
}
