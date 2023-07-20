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

#[derive(Clone, Default, Debug)]
pub struct Witness {
    pub bytecode: Vec<bytecode::Row>,
    pub copy: Vec<copy::Row>,
    pub core: Vec<core::Row>,
    pub exp: Vec<exp::Row>,
    pub public: Vec<public::Row>,
    pub state: Vec<state::Row>,
}

struct CurrentState {}

impl Witness {
    fn new(trace: Vec<Trace>) -> Self {
        unimplemented!()
    }
}
