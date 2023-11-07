use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// The byte value that is copied
    pub byte: U256,
    /// The source type, one of PublicCalldata, Memory, Bytecode, Calldata, Returndata
    pub src_type: Type,
    /// The source id, tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: U256,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: U256,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: Option<U256>,
    /// The destination type, one of Memory, Calldata, Returndata, PublicLog
    pub dst_type: Type,
    /// The destination id, tx_idx for PublicLog, call_id for Memory, Calldata, Returndata
    pub dst_id: U256,
    /// The destination pointer, for Calldata, Returndata, PublicLog means the index, for Memory means the address
    pub dst_pointer: U256,
    /// The destination stamp, state stamp for Memory, Calldata, Returndata. As for PublicLog it means the log_stamp
    pub dst_stamp: U256,
    /// The counter for one copy operation
    pub cnt: U256,
    /// The length for one copy operation
    pub len: U256,
}

/// Source and destination type.
/// Destination type could only be Memory, Calldata, Returndata, PublicLog, hence it needs two bits to represent.
/// Source type needs three bits.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub enum Type {
    #[default]
    /// Memory in state sub-circuit
    Memory,
    /// Calldata in state sub-circuit
    Calldata,
    /// Returndata in state sub-circuit
    Returndata,
    /// Log in public sub-circuit
    PublicLog,
    /// Calldata in public sub-circuit
    PublicCalldata,
    /// Bytecode in bytecode sub-circuit
    Bytecode,
}
