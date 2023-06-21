use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// various public information tag, e.g. BlockNumber, TxFrom
    pub tag: Tag,
    /// tx_id (start from 1), except for tag=BlockHash, means recent block number
    pub tx_id_or_block_number: U256,
    pub value0: U256,
    pub value1: U256,
    pub value2: U256,
    pub value3: U256,
    pub value4: U256,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub enum Tag {
    #[default]
    BlockCoinbase,
    BlockTimestamp,
    BlockNumber,
    BlockDifficulty,
    BlockGasLimit,
    BlockBaseFee,
    BlockHash,
    TxStatus,
    TxFrom,
    TxTo,
    TxIsCreate,
    TxNonce,
    TxGasLimit,
    TxValue,
    TxGasPrice,
    TxFeeCap,
    TxTipCap,
    TxCallData,
    TxLog,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum LogTag {
    Addr,
    Topic1,
    Topic2,
    Topic3,
    Topic4,
    Bytes,
}

#[cfg(test)]
mod test {
    use crate::witness::public::{LogTag, Row, Tag};
    use eth_types::U256;
    use serde::Serialize;
    use std::io;

    #[test]
    fn print_public_csv() {
        let row0 = Row {
            tag: Tag::BlockCoinbase,
            tx_id_or_block_number: U256::zero(),
            value0: U256::from(1023),
            value1: U256::max_value(),
            value2: U256::zero(),
            value3: U256::zero(),
            value4: U256::zero(),
        };
        let row1 = Row {
            tag: Tag::BlockGasLimit,
            ..Default::default()
        };
        let row2 = Row {
            tag: Tag::TxLog,
            tx_id_or_block_number: 1.into(),
            value0: 2.into(),
            value1: (LogTag::Addr as u8).into(),
            value2: U256::from(1023),
            value3: U256::max_value(),
            value4: 3.into(),
        };
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(&row0).unwrap();
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.flush().unwrap();
    }
}
