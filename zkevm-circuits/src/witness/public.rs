use std::collections::HashMap;

use crate::util::create_contract_addr_with_prefix;
use eth_types::geth_types::{BlockConstants, GethData};
use eth_types::{ToBigEndian, U256};
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// various public information tag, e.g. BlockNumber, TxFrom
    pub tag: Tag,
    /// tx_id (start from 1), except for tag=BlockHash, means recent block number diff (1...256)
    pub tx_idx_or_number_diff: Option<U256>,
    pub value_0: Option<U256>,
    pub value_1: Option<U256>,
    pub value_2: Option<U256>,
    pub value_3: Option<U256>,
    /// comments to show in html table that explain the purpose of each cell
    #[serde(skip_serializing)]
    pub comments: HashMap<String, String>,
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
    TxCalldata, //TODO make sure this equals copy tag PublicCalldata
    TxLog,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum LogTag {
    /// Tag for log source addr, also indicates 0 topic
    AddrWith0Topic,
    /// Tag for log source addr, also indicates 1 topic
    AddrWith1Topic,
    /// Tag for log source addr, also indicates 2 topic
    AddrWith2Topic,
    /// Tag for log source addr, also indicates 3 topic
    AddrWith3Topic,
    /// Tag for log source addr, also indicates 4 topic
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
            value_0: Some(block_constant.coinbase.as_fixed_bytes()[..4].into()),
            value_1: Some(block_constant.coinbase.as_fixed_bytes()[4..].into()),
            comments: [
                (format!("tag"), format!("BlockCoinbase")),
                (format!("value_0"), format!("BlockCoinbase[..4]")),
                (format!("value_1"), format!("BlockCoinbase[4..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockTimestamp,
            value_0: Some(block_constant.timestamp.to_be_bytes()[..16].into()),
            value_1: Some(block_constant.timestamp.to_be_bytes()[16..].into()),
            comments: [
                (format!("tag"), format!("BlockTimestamp")),
                (format!("value_0"), format!("BlockTimestamp[..16]")),
                (format!("value_1"), format!("BlockCoinbase[16..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockNumber,
            value_1: Some(block_constant.number.as_u64().into()),
            comments: [
                (format!("tag"), format!("BlockNumber")),
                (format!("value_1"), format!("BlockNumber as u64")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockDifficulty,
            value_0: Some(block_constant.difficulty.to_be_bytes()[..16].into()),
            value_1: Some(block_constant.difficulty.to_be_bytes()[16..].into()),
            comments: [
                (format!("tag"), format!("BlockDifficulty")),
                (format!("value_0"), format!("BlockDifficulty[..16]")),
                (format!("value_1"), format!("BlockDifficulty[16..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockGasLimit,
            value_0: Some(block_constant.gas_limit.to_be_bytes()[..16].into()),
            value_1: Some(block_constant.gas_limit.to_be_bytes()[16..].into()),
            comments: [
                (format!("tag"), format!("BlockGasLimit")),
                (format!("value_0"), format!("BlockGasLimit[..16]")),
                (format!("value_1"), format!("BlockGasLimit[16..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockBaseFee,
            value_0: Some(block_constant.base_fee.to_be_bytes()[..16].into()),
            value_1: Some(block_constant.base_fee.to_be_bytes()[16..].into()),
            comments: [
                (format!("tag"), format!("BlockBaseFee")),
                (format!("value_0"), format!("BlockBaseFee[..16]")),
                (format!("value_1"), format!("BlockBaseFee[16..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        for (tx_idx, tx) in geth_data.eth_block.transactions.iter().enumerate() {
            // due to we decide to start idx at 1 in witness
            let tx_idx = tx_idx + 1;
            result.push(Row {
                tag: Tag::TxFromValue,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some(tx.from.as_fixed_bytes()[..4].into()),
                value_1: Some(tx.from.as_fixed_bytes()[4..].into()),
                value_2: Some(tx.value.to_be_bytes()[..16].into()),
                value_3: Some(tx.value.to_be_bytes()[16..].into()),
                comments: [
                    (format!("tag"), format!("TxFromValue")),
                    (
                        format!("tx_idx_or_number_diff"),
                        format!("tx_idx{}", tx_idx),
                    ),
                    (format!("value_0"), format!("tx.from[..4]")),
                    (format!("value_1"), format!("tx.from[4..]")),
                    (format!("value_2"), format!("tx.value[..16]")),
                    (format!("value_3"), format!("tx.value[16..]")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            // to is 0x00ffffffffabcd... if tx is create (0xff... is prefix and first 0x00 is to prevent visiting outside of Fr)
            let (to_hi, to_lo): (U256, U256) = tx.to.map_or_else(
                || {
                    let to = create_contract_addr_with_prefix(&tx);
                    (to >> 128, to.low_u128().into())
                },
                |to| {
                    (
                        to.as_fixed_bytes()[..4].into(),
                        to.as_fixed_bytes()[4..].into(),
                    )
                },
            );
            result.push(Row {
                tag: Tag::TxToCallDataSize,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some(to_hi),
                value_1: Some(to_lo),
                value_2: Some(0.into()), //len won't > u128
                value_3: Some(tx.input.len().into()),
                comments: [
                    (format!("tag"), format!("TxToCallDataSize")),
                    (
                        format!("tx_idx_or_number_diff"),
                        format!("tx_idx={}", tx_idx),
                    ),
                    (format!("value_0"), format!("to_hi")),
                    (format!("value_1"), format!("to_low")),
                    (format!("value_2"), format!("0")),
                    (format!("value_3"), format!("tx.input.len")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            result.push(Row {
                tag: Tag::TxIsCreate,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some(0.into()),
                value_1: Some((tx.to.is_none() as u8).into()),
                comments: [
                    (format!("tag"), format!("TxIsCreate")),
                    (
                        format!("tx_idx_or_number_diff"),
                        format!("tx_idx{}", tx_idx),
                    ),
                    (format!("value_0"), format!("0")),
                    (format!("value_1"), format!("tx.to.is_none")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            result.push(Row {
                tag: Tag::TxGasLimit,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some(tx.gas.to_be_bytes()[..16].into()),
                value_1: Some(tx.gas.to_be_bytes()[16..].into()),
                comments: [
                    (format!("tag"), format!("TxGasLimit")),
                    (
                        format!("tx_idx_or_number_diff"),
                        format!("tx_idx{}", tx_idx),
                    ),
                    (format!("value_0"), format!("tx.gas[..16]")),
                    (format!("value_1"), format!("tx.gas[16..]")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            let gas_price = tx.gas_price.unwrap_or(0.into());
            result.push(Row {
                tag: Tag::TxGasPrice,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some(gas_price.to_be_bytes()[..16].into()),
                value_1: Some(gas_price.to_be_bytes()[16..].into()),
                comments: [
                    (format!("tag"), format!("TxGasPrice")),
                    (
                        format!("tx_idx_or_number_diff"),
                        format!("tx_idx{}", tx_idx),
                    ),
                    (format!("value_0"), format!("gas_price[..16]")),
                    (format!("value_1"), format!("gas_price[16..]")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            for (idx, byte) in tx.input.iter().enumerate() {
                result.push(Row {
                    tag: Tag::TxCalldata,
                    tx_idx_or_number_diff: Some(tx_idx.into()),
                    value_0: Some(idx.into()),
                    value_1: Some(tx.input.len().into()),
                    value_2: Some((*byte).into()),
                    comments: [
                        (format!("tag"), format!("TxCalldata")),
                        (
                            format!("tx_idx_or_number_diff"),
                            format!("tx_idx{}", tx_idx),
                        ),
                        (format!("value_0"), format!("idx")),
                        (format!("value_1"), format!("tx.input.len")),
                        (format!("value_2"), format!("byte")),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
            }
        }
        for (diff, hash) in geth_data.history_hashes.iter().rev().enumerate() {
            result.push(Row {
                tag: Tag::BlockHash,
                tx_idx_or_number_diff: Some((diff + 1).into()),
                value_0: Some(hash.to_be_bytes()[..16].into()),
                value_1: Some(hash.to_be_bytes()[16..].into()),
                comments: [
                    (format!("tag"), format!("BlockHash")),
                    (format!("tx_idx_or_number_diff"), format!("diff")),
                    (format!("value_0"), format!("hash[..16]")),
                    (format!("value_1"), format!("hash[16..]")),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
        }
        Ok(result)
    }
}
#[cfg(test)]
mod test {
    use crate::util::geth_data_test;
    use crate::witness::public::Row;
    use eth_types::GethExecTrace;

    #[test]
    fn from_geth_data() {
        let geth_data = geth_data_test(
            GethExecTrace {
                gas: 26809,
                failed: false,
                return_value: "".to_owned(),
                struct_logs: vec![],
            },
            &[12, 34, 56, 78],
            &[99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99],
            false,
        );
        let rows = Row::from_geth_data(&geth_data).unwrap();
        let mut wtr = csv::Writer::from_writer(vec![]);
        for row in &rows {
            wtr.serialize(row).unwrap();
        }
        let data = String::from_utf8(wtr.into_inner().unwrap()).unwrap();
        println!("{}", data);
    }
}
