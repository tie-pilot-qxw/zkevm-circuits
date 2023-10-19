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
    ReturnData,
    EndPadding,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub enum CallContextTag {
    #[default]
    ParentCallId,
    ParentCodeContractAddr,
    ParentProgramCounter,
    ParentStackPointer,
    StorageContractAddr,
    SenderAddr,
    Value,
    CallDataSize,
    ReturnDataCallId,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io;

    #[test]
    fn print_csv() {
        let row1 = Row {
            tag: Some(Tag::Memory),
            stamp: Some(2.into()),
            value_hi: Some(u128::MAX.into()),
            value_lo: Some(0.into()),
            is_write: Some((true as usize).into()),
            call_id_contract_addr: Some(1.into()),
            pointer_lo: Some(50.into()),
            ..Default::default()
        };
        let row2 = Row {
            tag: Some(Tag::CallContext),
            value_lo: Some(10.into()),
            pointer_lo: Some((CallContextTag::ParentProgramCounter as u8).into()),
            call_id_contract_addr: Some(3.into()),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.flush().unwrap();
    }
}
