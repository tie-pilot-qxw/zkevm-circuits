use crate::execution::ExecutionState;
use eth_types::evm_types::OpcodeId;
use eth_types::U256;
use serde::Serialize;
use std::collections::HashMap;

/// core row has a few single-purpose columns (tx_idx, call_id, code_addr, pc, opcode, cnt)
/// and 32 versatile columns
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    // the following columns are single purpose, non-versatile
    // transaction index of present opcode
    pub tx_idx: U256,
    // call id of present opcode
    pub call_id: U256,
    // contract address of the opcode
    pub code_addr: U256,
    // program counter of present opcode
    pub pc: U256,
    // opcode of present row
    pub opcode: OpcodeId,
    // counter for multi-row operation
    pub cnt: U256,
    // show the execution state to be human-readable, no used in circuit
    pub exec_state: Option<ExecutionState>,
    // 32 versatile columns used in all occasions
    pub vers_0: Option<U256>,
    pub vers_1: Option<U256>,
    pub vers_2: Option<U256>,
    pub vers_3: Option<U256>,
    pub vers_4: Option<U256>,
    pub vers_5: Option<U256>,
    pub vers_6: Option<U256>,
    pub vers_7: Option<U256>,
    pub vers_8: Option<U256>,
    pub vers_9: Option<U256>,
    pub vers_10: Option<U256>,
    pub vers_11: Option<U256>,
    pub vers_12: Option<U256>,
    pub vers_13: Option<U256>,
    pub vers_14: Option<U256>,
    pub vers_15: Option<U256>,
    pub vers_16: Option<U256>,
    pub vers_17: Option<U256>,
    pub vers_18: Option<U256>,
    pub vers_19: Option<U256>,
    pub vers_20: Option<U256>,
    pub vers_21: Option<U256>,
    pub vers_22: Option<U256>,
    pub vers_23: Option<U256>,
    pub vers_24: Option<U256>,
    pub vers_25: Option<U256>,
    pub vers_26: Option<U256>,
    pub vers_27: Option<U256>,
    pub vers_28: Option<U256>,
    pub vers_29: Option<U256>,
    pub vers_30: Option<U256>,
    pub vers_31: Option<U256>,
    #[serde(skip_serializing)]
    pub comments: HashMap<String, String>,
}

#[cfg(test)]
mod test {
    use crate::execution::ExecutionState;
    use crate::witness::core::Row;
    use eth_types::evm_types::OpcodeId;
    use eth_types::U256;
    use serde::Serialize;

    #[test]
    fn print_csv() {
        let row0 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 2.into(),
            ..Default::default()
        };
        let row1 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 1.into(),
            ..Default::default()
        };
        let row2 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 0.into(),
            exec_state: Some(ExecutionState::ADD),
            ..Default::default()
        };
        let row3 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 2.into(),
            exec_state: Some(ExecutionState::STOP),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        wtr.serialize(row0).unwrap();
        wtr.serialize(row1).unwrap();
        wtr.serialize(row2).unwrap();
        wtr.serialize(row3).unwrap();
        wtr.flush().unwrap();
    }
}
