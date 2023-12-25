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
    ChainId,
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
    TxGasPrice, // tx gas price
    TxCalldata, //TODO make sure this equals copy tag PublicCalldata
    TxLog,
    TxLogSize,
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
    Topic0,
    Topic1,
    Topic2,
    Topic3,
    Data,
    DataSize,
}

impl Row {
    /// Get all rows from geth data except TxStatus and TxLog since they don't exist there
    pub fn from_geth_data(geth_data: &GethData) -> Result<Vec<Row>, anyhow::Error> {
        let mut result = vec![];
        let block_constant: BlockConstants = (&geth_data.eth_block).try_into()?;
        result.push(Row {
            tag: Tag::ChainId,
            // chain_id high 16 byte
            value_0: Some(geth_data.chain_id.to_be_bytes()[..16].into()),
            // chain_id low 16 byte
            value_1: Some(geth_data.chain_id.to_be_bytes()[16..].into()),
            comments: [
                (format!("tag"), format!("ChainId")),
                (format!("value_0"), format!("ChainId[..16]")),
                (format!("value_1"), format!("ChainId[16..]")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockCoinbase,
            // coinbase high 4 byte
            value_0: Some(block_constant.coinbase.as_fixed_bytes()[..4].into()),
            // coinbase low 16 byte
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
            // timestamp high 16 byte
            value_0: Some(block_constant.timestamp.to_be_bytes()[..16].into()),
            // timestamp low 16 byte
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
            // block number as u64
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
            // difficulty high 16 byte
            value_0: Some(block_constant.difficulty.to_be_bytes()[..16].into()),
            // difficulty low 16 byte
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
            // gaslimit high 16 byte
            value_0: Some(block_constant.gas_limit.to_be_bytes()[..16].into()),
            // gaslimit low 16 byte
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
            // basefee hight 16 byte
            value_0: Some(block_constant.base_fee.to_be_bytes()[..16].into()),
            // basefee low 16 byte
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
            let gas_price = tx.gas_price.unwrap_or(0.into());
            result.push(Row {
                tag: Tag::TxFromValue,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                // tx.from high 4 byte
                value_0: Some(tx.from.as_fixed_bytes()[..4].into()),
                // tx.from low 4 byte
                value_1: Some(tx.from.as_fixed_bytes()[4..].into()),
                // tx.value high 16 byte
                value_2: Some(tx.value.to_be_bytes()[..16].into()),
                // tx.value low 16 byte
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
                // tx.input length
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
                // if isCreate 1 ,else 0
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
                // tx gas hight 16 byte
                value_0: Some(tx.gas.to_be_bytes()[..16].into()),
                // tx gas low 16 byte
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

            result.push(Row {
                tag: Tag::TxGasPrice,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                // tx gas_price high 16 byte
                value_0: Some(gas_price.to_be_bytes()[..16].into()),
                // tx gas_price low 16 byte
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
                    // input index
                    value_0: Some(idx.into()),
                    // input byte
                    value_1: Some((*byte).into()),
                    comments: [
                        (format!("tag"), format!("TxCalldata")),
                        (
                            format!("tx_idx_or_number_diff"),
                            format!("tx_idx{}", tx_idx),
                        ),
                        (format!("value_0"), format!("idx")),
                        (format!("value_1"), format!("byte")),
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
                // block number diff
                tx_idx_or_number_diff: Some((diff + 1).into()),
                // hash high 16 byte
                value_0: Some(hash.to_be_bytes()[..16].into()),
                // hash low 16 byte
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
        // log data inserts
        for log_data in &geth_data.logs {
            for log in log_data.logs.iter() {
                let topic_num = log.topics.len();
                // topic arrays length <= 4
                assert!(topic_num <= 4);
                let tx_idx = U256::from(log.transaction_index.unwrap_or_default().as_u64());
                let log_index = log.log_index.unwrap_or_default();
                // compute log_tag by log.topics.length
                let log_tag = if topic_num == 0 {
                    LogTag::AddrWith0Topic
                } else if topic_num == 1 {
                    LogTag::AddrWith1Topic
                } else if topic_num == 2 {
                    LogTag::AddrWith2Topic
                } else if topic_num == 3 {
                    LogTag::AddrWith3Topic
                } else {
                    LogTag::AddrWith4Topic
                };
                let address = log.address.as_bytes();
                // row0
                result.push(Row {
                    tag: Tag::TxLog,
                    tx_idx_or_number_diff: Some(tx_idx),
                    value_0: Some(log_index),
                    value_1: Some(U256::from(log_tag as u64)),
                    // address high 4 byte
                    value_2: Some(address[..4].into()),
                    // address low 16 byte
                    value_3: Some(address[4..].into()),
                    comments: [
                        (format!("tag"), format!("{:?}", Tag::TxLog)),
                        (
                            format!("tx_idx_or_number_diff"),
                            format!("transactionIndex"),
                        ),
                        (format!("value_0"), format!("logIndex")),
                        (format!("value_1"), format!("log_tag = {:?}", log_tag)),
                        (format!("value_2"), format!("address[..4]")),
                        (format!("value_3"), format!("address[4..]")),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
                for i in 0..topic_num {
                    // insert topic
                    let topic_hash = log.topics[i].as_bytes();
                    result.push(Self::get_log_topic_row(
                        i as u8,
                        topic_hash,
                        tx_idx,
                        log_index,
                        Self::get_log_topic_tag(i as u8),
                    ))
                }
                // insert log data size
                result.push(Row {
                    tag: Tag::TxLog,
                    tx_idx_or_number_diff: Some(tx_idx),
                    value_0: Some(log_index),
                    value_1: Some((LogTag::DataSize as u64).into()),
                    value_2: Some(0.into()),
                    // log data's length
                    value_1: Some(log.data.len().into()),
                    comments: [
                        (format!("tag"), format!("{:?}", Tag::TxLogSize)),
                        (
                            format!("tx_idx_or_number_diff"),
                            format!("transactionIndex"),
                        ),
                        (format!("value_0"), format!("log_index")),
                        (format!("value_1"), format!("log_tag = {}", "DataSize")),
                        (format!("value_1"), format!("0")),
                        (format!("value_1"), format!("data_len = {}", log.data.len())),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
                // insert log bytes
                for (data_idx, data) in log.data.iter().enumerate() {
                    result.push(Row {
                        tag: Tag::TxLog,
                        tx_idx_or_number_diff: Some(tx_idx),
                        value_0: Some(log_index),
                        value_1: Some(U256::from(LogTag::Data as u64)),
                        // log data byte
                        value_2: Some(U256::from(data.clone())),
                        // data byte index
                        value_3: Some(U256::from(data_idx as u64)),
                        comments: [
                            (format!("tag"), format!("{:?}", Tag::TxLog)),
                            (
                                format!("tx_idx_or_number_diff"),
                                format!("transactionIndex"),
                            ),
                            (format!("value_0"), format!("logIndex")),
                            (format!("value_1"), format!("log_tag = {:?}", LogTag::Data)),
                            (format!("value_2"), format!("byte")),
                            (format!("value_3"), format!("byte index")),
                        ]
                        .into_iter()
                        .collect(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(result)
    }

    // get_log_topic_tag return log topic tag
    fn get_log_topic_tag(idx: u8) -> LogTag {
        match idx {
            0 => LogTag::Topic0,
            1 => LogTag::Topic1,
            2 => LogTag::Topic2,
            3 => LogTag::Topic3,
            _ => panic!("illegal log_topic_tag"),
        }
    }
    // get_log_topic_row return topic row
    fn get_log_topic_row(
        topic_idx: u8,
        topic_hash: &[u8],
        tx_idx: U256,
        log_index: U256,
        log_tag: LogTag,
    ) -> Row {
        Row {
            tag: Tag::TxLog,
            tx_idx_or_number_diff: Some(tx_idx),
            value_0: Some(log_index),
            value_1: Some(U256::from(log_tag as u64)),
            value_2: Some(topic_hash[..16].into()),
            value_3: Some(topic_hash[16..].into()),
            comments: [
                (format!("tag"), format!("{:?}", Tag::TxLog)),
                (
                    format!("tx_idx_or_number_diff"),
                    format!("transactionIndex"),
                ),
                (format!("value_0"), format!("logIndex")),
                (format!("value_1"), format!("log_tag = {:?}", log_tag)),
                (
                    format!("value_2"),
                    format!("topicHash[{:}][..16]", topic_idx),
                ),
                (
                    format!("value_3"),
                    format!("topicHash[{:}][16..]", topic_idx),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    }
}
#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::util::geth_data_test;
    use crate::witness::public::Row;
    use eth_types::{Bytes, GethExecTrace, ReceiptLog, H160, H256, U256, U64};
    use ethers_core::types::Log;

    #[test]
    fn from_geth_data() {
        let log = ReceiptLog{
            logs:             vec![Log {
                address: H160::from_str("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512").unwrap(),
                topics: vec![H256::from_str(
                    "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93"
                )
                .unwrap(),],
                data: Bytes::from_str("0x000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000674041ba").unwrap(),
                block_hash: Some(H256::from_str("0xee573172d327d8c99739cd936344bb5567be6e794c6c1863ae97520af81803fe").unwrap()),
                block_number: Some(U64::from(4)),
                transaction_hash: Some(H256::from_str("0x15bc89db9525912ddb289c647ec4b473dc3b326eec95308d4dcb2d8a98de1b99").unwrap()),
                transaction_index: Some(U64::from(0)),
                log_index: Some(U256::from(0)),
                transaction_log_index: None,
                log_type: None,
                removed: Some(false)
            }]
        };
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
            log,
        );

        let rows = Row::from_geth_data(&geth_data);
        let mut wtr = csv::Writer::from_writer(vec![]);
        for row in &rows {
            wtr.serialize(row).unwrap();
        }
        let data = String::from_utf8(wtr.into_inner().unwrap()).unwrap();
        println!("{}", data);
    }
}
