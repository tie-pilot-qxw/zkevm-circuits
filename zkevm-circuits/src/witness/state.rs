use eth_types::U256;
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// Type of value, one of stack, memory, storage, call context, call data or return data
    pub tag: Option<Tag>,
    /// Stamp that increments for each state operation, unique for each row
    pub stamp: Option<U256>,
    /// High 128-bit value of the row
    pub value_hi: Option<U256>,
    /// Low 128-bit value of the row
    pub value_lo: Option<U256>,
    /// Call id (other types) or contract address (storage type only)
    pub call_id_contract_addr: Option<U256>,
    /// High 128-bit of the key (storage type only)
    pub pointer_hi: Option<U256>,
    /// Low 128-bit of the key (storage type only) or call context tag
    /// Or stack pointer or memory address or data index (call data and return data)
    pub pointer_lo: Option<U256>,
    /// Whether it is write or read, binary value
    pub is_write: Option<U256>,
    /// High 128-bit value_pre of the row
    /// The value of the last call to a similar command.
    pub value_pre_hi: Option<U256>,
    /// Low 128-bit value_pre of the row
    pub value_pre_lo: Option<U256>,
    /// High 128-bit committed_value of the row
    /// The value deposited in the previous transaction or the value of the previous block.
    pub committed_value_hi: Option<U256>,
    /// Low 128-bit committed_value of the row
    pub committed_value_lo: Option<U256>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    // in case for padding zeros, we make default = memory. memory read of unused pointer is 0.
    #[default]
    Memory,
    Stack,
    Storage,
    CallContext,
    CallData,
    // 对应EVM里的AddressInAccessList， key是address
    AddrInAccessListStorage,
    // 对应EVM里的SlotInAccessList， key是(address, slot)
    SlotInAccessListStorage,
    ReturnData,
    EndPadding,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

#[derive(Clone, Debug, Default, Serialize, Copy)]
pub enum CallContextTag {
    #[default]
    ParentCallId,
    ParentCodeContractAddr,
    ParentProgramCounter,
    ParentStackPointer,
    ParentGas,
    ParentGasCost,
    StorageContractAddr,
    SenderAddr,
    Value,
    CallDataSize,
    ReturnDataSize,
    ReturnDataCallId,
}
