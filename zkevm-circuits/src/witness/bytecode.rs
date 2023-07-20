use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// the contract address of the bytecodes
    pub addr: U256,
    /// the index that program counter points to
    pub pc: U256,
    /// bytecode, operation code or pushed value
    pub bytecode: U256,
    /// pushed value, high 128 bits
    pub value_hi: Option<U256>,
    /// pushed value, low 128 bits
    pub value_lo: Option<U256>,
    /// accumulated value, high 128 bits. accumulation will go X times for PUSHX
    pub acc_hi: Option<U256>,
    /// accumulated value, low 128 bits. accumulation will go X times for PUSHX
    pub acc_lo: Option<U256>,
    /// count for accumulation, accumulation will go X times for PUSHX
    pub cnt: U256,
    /// whether count is equal or larger than 16
    pub is_high: U256,
}

#[cfg(test)]
mod test {
    use eth_types::evm_types::OpcodeId;

    use super::*;
    use std::io;

    #[test]
    fn print_csv() {
        let row1 = Row {
            pc: U256::from(0x2),
            bytecode: OpcodeId::ADD.as_u8().into(),
            ..Default::default()
        };
        let row2 = Row {
            pc: 0x3.into(),
            bytecode: OpcodeId::PUSH1.as_u8().into(),
            cnt: 1.into(),
            value_lo: Some(3.into()),
            ..Default::default()
        };
        let row3 = Row {
            pc: 4.into(),
            bytecode: 3.into(),
            value_hi: Some(0.into()),
            value_lo: Some(3.into()),
            acc_hi: Some(0.into()),
            acc_lo: Some(3.into()),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.serialize(&row3).unwrap();
        wtr.flush().unwrap();
    }
}
