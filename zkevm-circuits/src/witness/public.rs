use crate::constant::PUBLIC_NUM_VALUES;
use crate::keccak_circuit::keccak_packed_multi::calc_keccak_hi_lo;
use crate::util::{convert_u256_to_64_bytes, create_contract_addr_with_prefix};
use eth_types::geth_types::{BlockConstants, GethData};
use eth_types::{Field, ToBigEndian, U256};
use serde::Serialize;
use std::collections::HashMap;

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

    // txs number in one block
    BlockTxNum,
    // the total number of logs in a block
    BlockLogNum,
    TxStatus,
    // combine From and Value together to reduce number of lookups
    TxFromValue,
    // combine To and CallDataLength together to reduce number of lookups
    TxToCallDataSize,
    // TxIsCreateCallDataGasCost :  include tx is create and call data gas cost
    TxIsCreateCallDataGasCost,
    TxGasLimit,
    TxGasPrice, // tx gas price
    TxCalldata,
    TxLog,
    TxLogSize,
    // bytecode size
    CodeSize,
    // bytecode hash
    CodeHash,
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
    // Data log data
    Data,
    // DataSize log data size
    DataSize,
}

impl Row {
    /// Get all rows from geth data except TxStatus and TxLog since they don't exist there
    pub fn from_geth_data(geth_data: &GethData) -> Result<Vec<Row>, anyhow::Error> {
        let mut result = vec![];
        let block_constant: BlockConstants = (&geth_data.eth_block).try_into()?;
        // | ChainId | 0 | chain_id[..16] | chain_id[16..] | 0 | 0 |
        result.push(Row {
            tag: Tag::ChainId,
            // chain_id high 16 byte
            value_0: Some(geth_data.chain_id.to_be_bytes()[..16].into()),
            // chain_id low 16 byte
            value_1: Some(geth_data.chain_id.to_be_bytes()[16..].into()),
            comments: [
                ("tag".into(), "ChainId".into()),
                ("value_0".into(), "ChainId[..16]".into()),
                ("value_1".into(), "ChainId[16..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockCoinbase | 0 | coinbase[..4] | coinbase[4..] | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockCoinbase,
            // coinbase high 4 byte
            value_0: Some(block_constant.coinbase.as_fixed_bytes()[..4].into()),
            // coinbase low 16 byte
            value_1: Some(block_constant.coinbase.as_fixed_bytes()[4..].into()),
            comments: [
                ("tag".into(), "BlockCoinbase".into()),
                ("value_0".into(), "BlockCoinbase[..4]".into()),
                ("value_1".into(), "BlockCoinbase[4..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockTimestamp | 0 | BlockTimestamp[..16] | BlockTimestamp[16..] | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockTimestamp,
            // timestamp high 16 byte
            value_0: Some(block_constant.timestamp.to_be_bytes()[..16].into()),
            // timestamp low 16 byte
            value_1: Some(block_constant.timestamp.to_be_bytes()[16..].into()),
            comments: [
                ("tag".into(), "BlockTimestamp".into()),
                ("value_0".into(), "BlockTimestamp[..16]".into()),
                ("value_1".into(), "BlockCoinbase[16..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockNumber | 0 | 0 | BlockNumber | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockNumber,
            // block number as u64
            value_1: Some(block_constant.number.as_u64().into()),
            comments: [
                ("tag".into(), "BlockNumber".into()),
                ("value_1".into(), "BlockNumber as u64".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockDifficulty | 0 | BlockDifficulty[..16] | BlockDifficulty[16..] | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockDifficulty,
            // difficulty high 16 byte
            value_0: Some(block_constant.difficulty.to_be_bytes()[..16].into()),
            // difficulty low 16 byte
            value_1: Some(block_constant.difficulty.to_be_bytes()[16..].into()),
            comments: [
                ("tag".into(), "BlockDifficulty".into()),
                ("value_0".into(), "BlockDifficulty[..16]".into()),
                ("value_1".into(), "BlockDifficulty[16..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockGasLimit | 0 | BlockGasLimit[..16] | BlockGasLimit[16..] | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockGasLimit,
            // gaslimit high 16 byte
            value_0: Some(block_constant.gas_limit.to_be_bytes()[..16].into()),
            // gaslimit low 16 byte
            value_1: Some(block_constant.gas_limit.to_be_bytes()[16..].into()),
            comments: [
                ("tag".into(), "BlockGasLimit".into()),
                ("value_0".into(), "BlockGasLimit[..16]".into()),
                ("value_1".into(), "BlockGasLimit[16..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // | BlockBaseFee | 0 | BlockBaseFee[..16] | BlockBaseFee[16..] | 0 | 0 |
        result.push(Row {
            tag: Tag::BlockBaseFee,
            // basefee high 16 byte
            value_0: Some(block_constant.base_fee.to_be_bytes()[..16].into()),
            // basefee low 16 byte
            value_1: Some(block_constant.base_fee.to_be_bytes()[16..].into()),
            comments: [
                ("tag".into(), "BlockBaseFee".into()),
                ("value_0".into(), "BlockBaseFee[..16]".into()),
                ("value_1".into(), "BlockBaseFee[16..]".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        result.push(Row {
            tag: Tag::BlockTxNum,
            value_0: Some(geth_data.eth_block.transactions.len().into()),
            comments: [
                (format!("tag"), format!("BlockTxNum")),
                (format!("value_0"), format!("txNumber")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        for (tx_idx, tx) in geth_data.eth_block.transactions.iter().enumerate() {
            // due to we decide to start idx at 1 in witness
            let tx_idx = tx_idx + 1;
            let gas_price = tx.gas_price.unwrap_or(0.into());
            // | TxFromValue | tx_idx  | from[..4] | from[4..] | value[..16] | value[16..] |
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
                    ("tag".into(), "TxFromValue".into()),
                    ("tx_idx_or_number_diff".into(), format!("tx_idx{}", tx_idx)),
                    ("value_0".into(), "tx.from[..4]".into()),
                    ("value_1".into(), "tx.from[4..]".into()),
                    ("value_2".into(), "tx.value[..16]".into()),
                    ("value_3".into(), "tx.value[16..]".into()),
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
            // | TxToCallDataSize | tx_idx  | to_hi | to_lo | 0 | tx.input.len |
            result.push(Row {
                tag: Tag::TxToCallDataSize,
                tx_idx_or_number_diff: Some(tx_idx.into()),

                value_0: Some(to_hi),
                value_1: Some(to_lo),
                value_2: Some(0.into()), //len won't > u128
                // tx.input length
                value_3: Some(tx.input.len().into()),
                comments: [
                    ("tag".into(), "TxToCallDataSize".into()),
                    ("tx_idx_or_number_diff".into(), format!("tx_idx={}", tx_idx)),
                    ("value_0".into(), "to_hi".into()),
                    ("value_1".into(), "to_low".into()),
                    ("value_2".into(), "0".into()),
                    ("value_3".into(), "tx.input.len".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            // | TxIsCreate | tx_idx  | 1/0(if create contract is 1,else 0) | call data gas cost | call data size | 0 |
            let call_data_gas_cost =
                eth_types::geth_types::Transaction::from(tx).call_data_gas_cost();
            result.push(Row {
                tag: Tag::TxIsCreateCallDataGasCost,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                value_0: Some((tx.to.is_none() as u8).into()),
                // if isCreate 1 ,else 0
                value_1: Some(call_data_gas_cost.into()),
                value_2: Some(tx.input.len().into()),
                comments: [
                    ("tag".into(), "TxIsCreate".into()),
                    ("tx_idx_or_number_diff".into(), format!("tx_idx{}", tx_idx)),
                    ("value_0".into(), "tx.to.is_none".into()),
                    ("value_1".into(), "call data gas cost".into()),
                    ("value_2".into(), "call data size".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            // | TxGasLimit | tx_idx  | gas[..16] | gas[16..] | 0 | 0 |
            result.push(Row {
                tag: Tag::TxGasLimit,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                // tx gas high 16 byte
                value_0: Some(tx.gas.to_be_bytes()[..16].into()),
                // tx gas low 16 byte
                value_1: Some(tx.gas.to_be_bytes()[16..].into()),
                comments: [
                    ("tag".into(), "TxGasLimit".into()),
                    ("tx_idx_or_number_diff".into(), format!("tx_idx{}", tx_idx)),
                    ("value_0".into(), "tx.gas[..16]".into()),
                    ("value_1".into(), "tx.gas[16..]".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            // | TxGasPrice | tx_idx  | gas_price[..16] | gas_price[16..] | 0 | 0 |
            result.push(Row {
                tag: Tag::TxGasPrice,
                tx_idx_or_number_diff: Some(tx_idx.into()),
                // tx gas_price high 16 byte
                value_0: Some(gas_price.to_be_bytes()[..16].into()),
                // tx gas_price low 16 byte
                value_1: Some(gas_price.to_be_bytes()[16..].into()),
                comments: [
                    ("tag".into(), "TxGasPrice".into()),
                    ("tx_idx_or_number_diff".into(), format!("tx_idx{}", tx_idx)),
                    ("value_0".into(), "gas_price[..16]".into()),
                    ("value_1".into(), "gas_price[16..]".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
            for (idx, byte) in tx.input.iter().enumerate() {
                // | TxCalldata | tx_idx  | idx | byte | 0 | 0 |
                result.push(Row {
                    tag: Tag::TxCalldata,
                    // tx index
                    tx_idx_or_number_diff: Some(tx_idx.into()),
                    // input index
                    value_0: Some(idx.into()),
                    // input byte
                    value_1: Some((*byte).into()),
                    comments: [
                        ("tag".into(), "TxCalldata".into()),
                        ("tx_idx_or_number_diff".into(), format!("tx_idx{}", tx_idx)),
                        ("value_0".into(), "idx".into()),
                        ("value_1".into(), "byte".into()),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
            }
        }
        for (diff, hash) in geth_data.history_hashes.iter().rev().enumerate() {
            // | BlockHash | index  | hash[..16] | hash[16..] | 0 | 0 |
            result.push(Row {
                tag: Tag::BlockHash,
                // block number diff
                tx_idx_or_number_diff: Some((diff + 1).into()),
                // hash high 16 byte
                value_0: Some(hash.to_be_bytes()[..16].into()),
                // hash low 16 byte
                value_1: Some(hash.to_be_bytes()[16..].into()),
                comments: [
                    ("tag".into(), "BlockHash".into()),
                    ("tx_idx_or_number_diff".into(), "diff".into()),
                    ("value_0".into(), "hash[..16]".into()),
                    ("value_1".into(), "hash[16..]".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
        }

        // The total number of logs in a block
        let log_num: usize = geth_data
            .logs
            .iter()
            .map(|log_data| log_data.logs.len())
            .sum();

        result.push(Row {
            tag: Tag::BlockLogNum,
            value_0: Some(log_num.into()),
            comments: [
                ("tag".into(), "BlockLogNum".into()),
                ("value_0".into(), "logNum".into()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });

        // log data inserts
        for log_data in &geth_data.logs {
            for log in log_data.logs.iter() {
                let topic_num = log.topics.len();
                // topic arrays length <= 4
                assert!(topic_num <= 4);
                let tx_idx = U256::from(log.transaction_index.unwrap_or_default().as_u64()) + 1;
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
                // log.address is H160, 20 bytes
                let address = log.address.as_bytes();
                // row0
                // | TxLog | tx_idx  | log_index | log_tag | address[..4] | address[4..] |
                result.push(Row {
                    tag: Tag::TxLog,
                    tx_idx_or_number_diff: Some(tx_idx),
                    // log_index = log.index
                    value_0: Some(log_index),
                    // log_tag should be LogTag::AddrWith[0/1/2/3/4]Topic
                    value_1: Some(U256::from(log_tag as u64)),
                    // address high 4 byte
                    value_2: Some(address[..4].into()),
                    // address low 16 byte
                    value_3: Some(address[4..].into()),
                    comments: [
                        ("tag".into(), format!("{:?}", Tag::TxLog)),
                        ("tx_idx_or_number_diff".into(), "transactionIndex".into()),
                        ("value_0".into(), "logIndex".into()),
                        ("value_1".into(), format!("log_tag = {:?}", log_tag)),
                        ("value_2".into(), "address[..4]".into()),
                        ("value_3".into(), "address[4..]".into()),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
                for i in 0..topic_num {
                    // insert topic
                    let topic_hash = log.topics[i].as_bytes();
                    // | TxLog | tx_idx  | log_index | topic_log_tag | topic_hash[..16] | topic_hash[16..] |
                    result.push(Self::get_log_topic_row(
                        i as u8,
                        topic_hash,
                        tx_idx,
                        log_index,
                        Self::get_log_topic_tag(i as u8),
                    ))
                }
                // insert log data size
                // | TxLog | tx_idx  | log_index | log_tag=DataSize | 0 | data_len |
                result.push(Row {
                    tag: Tag::TxLog,
                    tx_idx_or_number_diff: Some(tx_idx),
                    value_0: Some(log_index),
                    value_1: Some((LogTag::DataSize as u64).into()),
                    value_2: Some(0.into()),
                    // log data's length
                    value_3: Some(log.data.len().into()),
                    comments: [
                        ("tag".into(), format!("{:?}", Tag::TxLogSize)),
                        ("tx_idx_or_number_diff".into(), "transactionIndex".into()),
                        ("value_0".into(), "log_index".into()),
                        ("value_1".into(), format!("log_tag = {}", "DataSize")),
                        ("value_2".into(), "0".into()),
                        ("value_3".into(), format!("data_len = {}", log.data.len())),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                });
                // insert log bytes
                // | TxLog | tx_idx  | log_index | LogTag::Data | byte | data_idx |
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
                            ("tag".into(), format!("{:?}", Tag::TxLog)),
                            ("tx_idx_or_number_diff".into(), "transactionIndex".into()),
                            ("value_0".into(), "logIndex".into()),
                            ("value_1".into(), format!("log_tag = {:?}", LogTag::Data)),
                            ("value_2".into(), "byte".into()),
                            ("value_3".into(), "byte index".into()),
                        ]
                        .into_iter()
                        .collect(),
                        ..Default::default()
                    });
                }
            }
        }

        // code size and code hash
        for account in geth_data.accounts.iter() {
            let addr_hi = account.address >> 128;
            let addr_lo = U256::from(account.address.low_u128());
            let code_size = account.code.len();
            let (code_hash_hi, code_hash_lo) = calc_keccak_hi_lo(account.code.as_ref());

            // push code size
            result.push(Row {
                tag: Tag::CodeSize,
                value_0: Some(addr_hi),
                value_1: Some(addr_lo),
                value_2: Some(U256::zero()),
                value_3: Some(U256::from(code_size)),
                comments: [
                    ("tag".into(), "CodeSize".into()),
                    ("value_0".into(), "address_hi".into()),
                    ("value_1".into(), "address_lo".into()),
                    ("value_2".into(), "code_size hi".into()),
                    ("value_3".into(), "code_size lo".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });

            // push code hash
            result.push(Row {
                tag: Tag::CodeHash,
                value_0: Some(addr_hi),
                value_1: Some(addr_lo),
                value_2: Some(U256::from(code_hash_hi)),
                value_3: Some(U256::from(code_hash_lo)),
                comments: [
                    ("tag".into(), "CodeHash".into()),
                    ("value_0".into(), "address_hi".into()),
                    ("value_1".into(), "address_lo".into()),
                    ("value_2".into(), "code_hash_hi".into()),
                    ("value_3".into(), "code_hash_lo".into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            });
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
            // log_tag should be LogTag::Topic0/Topic1/Topic2/Topic3
            value_1: Some(U256::from(log_tag as u64)),
            value_2: Some(topic_hash[..16].into()),
            value_3: Some(topic_hash[16..].into()),
            comments: [
                ("tag".into(), format!("{:?}", Tag::TxLog)),
                ("tx_idx_or_number_diff".into(), "transactionIndex".into()),
                ("value_0".into(), "logIndex".into()),
                ("value_1".into(), format!("log_tag = {:?}", log_tag)),
                ("value_2".into(), format!("topicHash[{:}][..16]", topic_idx)),
                ("value_3".into(), format!("topicHash[{:}][16..]", topic_idx)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    }
}

/// Get instance from witness.public (`&[Row]`), return a vector of vector of F
pub fn public_rows_to_instance<F: Field>(rows: &[Row]) -> Vec<Vec<F>> {
    let mut tag = vec![];
    let mut tx_idx_or_number_diff = vec![];
    let mut values: [Vec<F>; PUBLIC_NUM_VALUES] = std::array::from_fn(|_| vec![]);
    // assign values from witness of public
    for row in rows {
        tag.push(F::from_u128(row.tag as u128));
        // tx_idx_or_number_diff to little endian,u64
        tx_idx_or_number_diff.push(F::from_uniform_bytes(&convert_u256_to_64_bytes(
            &row.tx_idx_or_number_diff.unwrap_or_default(),
        )));
        let array: [_; PUBLIC_NUM_VALUES] = [row.value_0, row.value_1, row.value_2, row.value_3];
        for i in 0..PUBLIC_NUM_VALUES {
            // value[i] to little endian,u64
            values[i].push(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &array[i].unwrap_or_default(),
            )));
        }
    }
    let mut res: Vec<Vec<F>> = vec![tag, tx_idx_or_number_diff];
    res.extend(values);
    res
}

#[cfg(test)]
mod test {
    use crate::util::geth_data_test;
    use crate::witness::public::Row;
    use eth_types::{Bytes, GethExecTrace, ReceiptLog, H160, H256, U256, U64};
    use ethers_core::types::Log;
    use std::str::FromStr;

    #[test]
    fn from_geth_data() {
        // mock receiptLog
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
        // mock GethData
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
        // get all public rows using GethData
        let rows = Row::from_geth_data(&geth_data);
        // new csv writer
        let mut wtr = csv::Writer::from_writer(vec![]);
        // serialize row
        for row in &rows {
            wtr.serialize(row).unwrap();
        }
        // output in console
        let data = String::from_utf8(wtr.into_inner().unwrap()).unwrap();
        println!("{}", data);
    }
}
