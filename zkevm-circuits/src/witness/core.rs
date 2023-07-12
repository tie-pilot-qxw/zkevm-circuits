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
    // 32 values used in all occasions
    pub vers0: Option<U256>,
    pub vers1: Option<U256>,
    pub vers2: Option<U256>,
    pub vers3: Option<U256>,
    pub vers4: Option<U256>,
    pub vers5: Option<U256>,
    pub vers6: Option<U256>,
    pub vers7: Option<U256>,
    pub vers8: Option<U256>,
    pub vers9: Option<U256>,
    pub vers10: Option<U256>,
    pub vers11: Option<U256>,
    pub vers12: Option<U256>,
    pub vers13: Option<U256>,
    pub vers14: Option<U256>,
    pub vers15: Option<U256>,
    pub vers16: Option<U256>,
    pub vers17: Option<U256>,
    pub vers18: Option<U256>,
    pub vers19: Option<U256>,
    pub vers20: Option<U256>,
    pub vers21: Option<U256>,
    pub vers22: Option<U256>,
    pub vers23: Option<U256>,
    pub vers24: Option<U256>,
    pub vers25: Option<U256>,
    pub vers26: Option<U256>,
    pub vers27: Option<U256>,
    pub vers28: Option<U256>,
    pub vers29: Option<U256>,
    pub vers30: Option<U256>,
    pub vers31: Option<U256>,
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
