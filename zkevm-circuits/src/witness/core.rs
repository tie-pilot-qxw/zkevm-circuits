use eth_types::evm_types::OpcodeId;
use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
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
}

pub enum ExecutionState {
    PUSH,
    ADD,
    STOP,
}

impl ExecutionState {
    pub fn to_core_row(self) -> Row {
        let op = self as usize;
        assert!(op < 100);
        let mut selector_hi = [0; 10];
        selector_hi[op / 10] = 1;
        let mut selector_lo = [0; 10];
        selector_lo[op % 10] = 1;
        Row {
            vers_0: Some(selector_hi[0].into()),
            vers_1: Some(selector_hi[1].into()),
            vers_2: Some(selector_hi[2].into()),
            vers_3: Some(selector_hi[3].into()),
            vers_4: Some(selector_hi[4].into()),
            vers_5: Some(selector_hi[5].into()),
            vers_6: Some(selector_hi[6].into()),
            vers_7: Some(selector_hi[7].into()),
            vers_8: Some(selector_hi[8].into()),
            vers_9: Some(selector_hi[9].into()),
            vers_10: Some(selector_lo[0].into()),
            vers_11: Some(selector_lo[1].into()),
            vers_12: Some(selector_lo[2].into()),
            vers_13: Some(selector_lo[3].into()),
            vers_14: Some(selector_lo[4].into()),
            vers_15: Some(selector_lo[5].into()),
            vers_16: Some(selector_lo[6].into()),
            vers_17: Some(selector_lo[7].into()),
            vers_18: Some(selector_lo[8].into()),
            vers_19: Some(selector_lo[9].into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::witness::core::Row;
    use eth_types::evm_types::OpcodeId;
    use eth_types::U256;
    use serde::Serialize;
    #[test]
    fn print_csv() {
        let Row0 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 2.into(),
            ..Default::default()
        };
        let Row1 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 1.into(),
            ..Default::default()
        };
        let Row2 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 0.into(),
            ..Default::default()
        };
        let Row3 = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffffffffff", 16).unwrap(),
            pc: 2.into(),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        wtr.serialize(Row0).unwrap();
        wtr.serialize(Row1).unwrap();
        wtr.serialize(Row2).unwrap();
        wtr.serialize(Row3).unwrap();
        wtr.flush().unwrap();
    }
}
