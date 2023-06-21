use eth_types::geth_types::{BlockConstants, GethData};
use eth_types::{Address, ToBigEndian, H256, U256};
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// various public information tag, e.g. BlockNumber, TxFrom
    pub tag: Tag,
    /// tx_id (start from 1), except for tag=BlockHash, means recent block number diff (1...256)
    pub tx_idx_or_number_diff: U256,
    pub value0: U256,
    pub value1: U256,
    pub value2: U256,
    pub value3: U256,
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
    // combine From and Value together to reduce number of lookups
    TxFromValue,
    // combine To and CallDataLength together to reduce number of lookups
    TxToCallDataSize,
    TxIsCreate,
    TxGasLimit,
    TxGasPrice,
    TxCallData,
    TxLog,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum LogTag {
    AddrWith0Topic,
    AddrWith1Topic,
    AddrWith2Topic,
    AddrWith3Topic,
    AddrWith4Topic,
    Topic1,
    Topic2,
    Topic3,
    Topic4,
    Bytes,
}

impl Row {
    /// Get all rows from geth data except TxStatus and TxLog since they don't exist there
    pub fn from_geth_data(geth_data: &GethData) -> Result<Vec<Row>, anyhow::Error> {
        let mut result = vec![];
        let block_constant: BlockConstants = (&geth_data.eth_block).try_into()?;
        result.push(Row {
            tag: Tag::BlockCoinbase,
            value0: block_constant.coinbase.as_fixed_bytes()[..4].into(),
            value1: block_constant.coinbase.as_fixed_bytes()[4..].into(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockTimestamp,
            value0: block_constant.timestamp.to_be_bytes()[..16].into(),
            value1: block_constant.timestamp.to_be_bytes()[16..].into(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockNumber,
            value1: block_constant.number.as_u64().into(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockDifficulty,
            value0: block_constant.difficulty.to_be_bytes()[..16].into(),
            value1: block_constant.difficulty.to_be_bytes()[16..].into(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockGasLimit,
            value0: block_constant.gas_limit.to_be_bytes()[..16].into(),
            value1: block_constant.gas_limit.to_be_bytes()[16..].into(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockBaseFee,
            value0: block_constant.base_fee.to_be_bytes()[..16].into(),
            value1: block_constant.base_fee.to_be_bytes()[16..].into(),
            ..Default::default()
        });
        for (tx_idx, tx) in geth_data.eth_block.transactions.iter().enumerate() {
            result.push(Row {
                tag: Tag::TxFromValue,
                tx_idx_or_number_diff: (tx_idx + 1).into(),
                value0: tx.from.as_fixed_bytes()[..4].into(),
                value1: tx.from.as_fixed_bytes()[4..].into(),
                value2: tx.value.to_be_bytes()[..16].into(),
                value3: tx.value.to_be_bytes()[16..].into(),
                ..Default::default()
            });
            // to is 0xffffffff00000000...idx if tx is create
            let to = tx.to.unwrap_or(
                <&[u8] as TryInto<[u8; 20]>>::try_into(
                    u32::MAX
                        .to_be_bytes()
                        .into_iter()
                        .chain(((tx_idx + 1) as u128).to_be_bytes().into_iter())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .unwrap()
                .into(),
            );
            result.push(Row {
                tag: Tag::TxToCallDataSize,
                tx_idx_or_number_diff: (tx_idx + 1).into(),
                value0: to.as_fixed_bytes()[..4].into(),
                value1: to.as_fixed_bytes()[4..].into(),
                value2: 0.into(), //len won't > u128
                value3: tx.input.len().into(),
                ..Default::default()
            });
            result.push(Row {
                tag: Tag::TxIsCreate,
                tx_idx_or_number_diff: (tx_idx + 1).into(),
                value0: 0.into(),
                value1: (tx.to.is_none() as u8).into(),
                ..Default::default()
            });
            result.push(Row {
                tag: Tag::TxGasLimit,
                tx_idx_or_number_diff: (tx_idx + 1).into(),
                value0: tx.gas.to_be_bytes()[..16].into(),
                value1: tx.gas.to_be_bytes()[16..].into(),
                ..Default::default()
            });
            let gas_price = tx.gas_price.unwrap_or(0.into());
            result.push(Row {
                tag: Tag::TxGasPrice,
                tx_idx_or_number_diff: (tx_idx + 1).into(),
                value0: gas_price.to_be_bytes()[..16].into(),
                value1: gas_price.to_be_bytes()[16..].into(),
                ..Default::default()
            });
            for (idx, byte) in tx.input.iter().enumerate() {
                result.push(Row {
                    tag: Tag::TxCallData,
                    tx_idx_or_number_diff: (tx_idx + 1).into(),
                    value0: idx.into(),
                    value1: tx.input.len().into(),
                    value2: (*byte).into(),
                    ..Default::default()
                });
            }
        }
        for (diff, hash) in geth_data.history_hashes.iter().rev().enumerate() {
            result.push(Row {
                tag: Tag::BlockHash,
                tx_idx_or_number_diff: (diff + 1).into(),
                value0: hash.to_be_bytes()[..16].into(),
                value1: hash.to_be_bytes()[16..].into(),
                ..Default::default()
            });
        }
        Ok(result)
    }
}
#[cfg(test)]
mod test {
    use crate::witness::public::{LogTag, Row, Tag};
    use eth_types::geth_types::GethData;
    use eth_types::{Block, Transaction, U256};
    use serde::Serialize;
    use std::io;

    fn get_test_geth_data() -> GethData {
        let mut history_hashes = vec![];
        for i in 0..256 {
            history_hashes.push(i.into())
        }
        let tx1 = Transaction {
            value: 400000.into(),
            from: [5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8].into(),
            to: Some(
                [
                    9, 10, 11, 12, 9, 10, 11, 12, 9, 10, 11, 12, 9, 10, 11, 12, 9, 10, 11, 12,
                ]
                .into(),
            ),
            gas: 0x10000.into(),
            input: vec![99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99].into(),
            ..Default::default()
        };
        let eth_block = Block {
            author: Some([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4].into()),
            number: Some(12345.into()),
            base_fee_per_gas: Some(1.into()),
            gas_limit: 0x200000.into(),
            transactions: vec![tx1],
            ..Default::default()
        };
        GethData {
            chain_id: 42.into(),
            history_hashes,
            eth_block,
            geth_traces: vec![],
            accounts: vec![],
        }
    }

    #[test]
    fn from_geth_data() {
        let geth_data = get_test_geth_data();
        let rows = Row::from_geth_data(&geth_data).unwrap();
        let mut wtr = csv::Writer::from_writer(io::stdout());
        for row in &rows {
            wtr.serialize(row).unwrap();
        }
        wtr.flush().unwrap();
    }

    #[test]
    fn print_public_csv() {
        let row0 = Row {
            tag: Tag::BlockCoinbase,
            tx_idx_or_number_diff: U256::zero(),
            value0: U256::from(1023),
            value1: U256::max_value(),
            value2: U256::zero(),
            value3: U256::zero(),
        };
        let row1 = Row {
            tag: Tag::BlockGasLimit,
            ..Default::default()
        };
        let row2 = Row {
            tag: Tag::TxLog,
            tx_idx_or_number_diff: 1.into(),
            value0: 2.into(),
            value1: (LogTag::AddrWith3Topic as u8).into(),
            value2: U256::from(1023),
            value3: U256::max_value(),
        };
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(&row0).unwrap();
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.flush().unwrap();
    }
}
