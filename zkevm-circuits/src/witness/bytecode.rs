use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// the contract address of the bytecodes
    pub addr: Option<U256>,
    /// the index that program counter points to
    pub pc: Option<U256>,
    /// bytecode, operation code or pushed value
    pub bytecode: Option<U256>,
    /// pushed value, high 128 bits (0 or non-push opcodes)
    pub value_hi: Option<U256>,
    /// pushed value, low 128 bits (0 or non-push opcodes)
    pub value_lo: Option<U256>,
    /// accumulated value, high 128 bits. accumulation will go X times for PUSHX
    pub acc_hi: Option<U256>,
    /// accumulated value, low 128 bits. accumulation will go X times for PUSHX
    pub acc_lo: Option<U256>,
    /// count for accumulation, accumulation will go X times for PUSHX
    pub cnt: Option<U256>,
    /// whether count is equal or larger than 16
    pub is_high: Option<U256>,
}
