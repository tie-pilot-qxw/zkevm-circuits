use eth_types::U256;
use serde::Serialize;
use strum::IntoEnumIterator;

use strum_macros::{EnumIter, EnumString};
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    // Type of value, one of stack, memory, storage, call context, call data or return data
    pub tag: Tag,
    // auto increment stamp, unique for each row
    pub stamp: U256,
    // hi 128 bit value of each row
    pub value_hi: Option<U256>,
    // low 128 bit value of each row
    pub value_lo: Option<U256>,
    // call id or contract address (storage type only)
    pub call_id_contract_addr: Option<U256>,
    // size of call data or hi 128 bit of pointer (storage type only)
    pub pointer_hi: Option<U256>,
    // low 128 pointer or call context tag, one of parent call id, program counter,
    // code contract addr, storage contract addr, value, call data size or return data call id
    pub pointer_lo: Option<U256>,
    // whether the value is write, especially for stack, memory or storage
    pub is_write: Option<U256>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    #[default]
    Stack,
    Memory,
    Storage,
    CallContext,
    CallData,
    ReturnData,
}
impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

#[derive(Clone, Debug, Default, Serialize)]
enum CallContextTag {
    #[default]
    ParentCallId,
    ProgramCounter,
    StackPointer,
    CodeContractAddr,
    StorageContractAddr,
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
            tag: Tag::Memory,
            stamp: U256::from(2),
            value_hi: Some(u128::MAX.into()),
            value_lo: Some(0.into()),
            is_write: Some((true as usize).into()),
            call_id_contract_addr: Some(1.into()),
            pointer_lo: Some(50.into()),
            ..Default::default()
        };
        let row2 = Row {
            tag: Tag::CallContext,
            value_lo: Some(10.into()),
            pointer_lo: Some((CallContextTag::ProgramCounter as u8).into()),
            call_id_contract_addr: Some(3.into()),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.flush().unwrap();
    }
}
