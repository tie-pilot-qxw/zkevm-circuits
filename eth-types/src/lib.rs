//! Ethereum and Evm types used to deserialize responses from web3 / geth.

#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(non_snake_case)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
//#![deny(unsafe_code)] Allowed now until we find a
// better way to handle downcasting from Operation into it's variants.
#![allow(clippy::upper_case_acronyms)] // Too pedantic
#![feature(lazy_cell)]

use std::fmt::Display;
use std::{collections::HashMap, fmt, str::FromStr};

use ethers_core::types::{self, Log};
pub use ethers_core::{
    abi::ethereum_types::{BigEndianHash, U512},
    types::{
        transaction::{eip2930::AccessList, response::Transaction},
        Address, Block, Bytes, Signature, H160, H256, H64, U256, U64,
    },
};
use halo2_proofs::halo2curves::{
    bn256::{Fq, Fr},
    ff::{Field as Halo2Field, FromUniformBytes, PrimeField},
};
use serde::{de, Deserialize, Serialize};

use crate::call_types::GethCallTrace;
use crate::evm_types::{memory::Memory, stack::Stack, storage::Storage, OpcodeId};

#[macro_use]
pub mod macros;
#[macro_use]
pub mod error;
#[macro_use]
pub mod bytecode;
pub mod call_types;
pub mod evm_types;
pub mod geth_types;
pub mod keccak;
pub mod sign_types;
pub mod state_db;

pub use bytecode::Bytecode;
pub use error::Error;
pub use keccak::{keccak256, Keccak};
use poseidon_circuit::Hashable;
pub use state_db::StateDB;
pub use uint_types::DebugU256;

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field:
    Halo2Field + PrimeField<Repr = [u8; 32]> + FromUniformBytes<64> + Ord + Hashable
{
    /// Re-expose zero element as a function
    fn zero() -> Self {
        Self::ZERO
    }
    /// Gets the lower 128 bits of this field element when expressed
    /// canonically.
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes[..16]
            .iter()
            .rev()
            .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }
    /// Gets the lower 32 bits of this field element when expressed
    /// canonically.
    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes[..4]
            .iter()
            .rev()
            .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
// impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

// We use our own declaration of another U256 in order to implement a custom
// deserializer that can parse U256 when returned by structLogs fields in geth
// debug_trace* methods, which don't contain the `0x` prefix.
#[allow(clippy::all)]
mod uint_types {
    uint::construct_uint! {
        /// 256-bit unsigned integer.
        pub struct DebugU256(4);
    }
}

impl<'de> Deserialize<'de> for DebugU256 {
    fn deserialize<D>(deserializer: D) -> Result<DebugU256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DebugU256::from_str(&s).map_err(de::Error::custom)
    }
}

impl<F: Field> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToBigEndian for DebugU256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToWord for DebugU256 {
    fn to_word(&self) -> Word {
        U256(self.0)
    }
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for u128 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for usize {
    fn to_word(&self) -> Word {
        u64::try_from(*self)
            .expect("usize bigger than u64")
            .to_word()
    }
}

impl ToWord for i32 {
    fn to_word(&self) -> Word {
        let value = Word::from(self.unsigned_abs() as u64);
        if self.is_negative() {
            value.overflowing_neg().0
        } else {
            value
        }
    }
}

impl ToWord for U64 {
    fn to_word(&self) -> Word {
        self.as_u64().into()
    }
}

impl ToWord for Word {
    fn to_word(&self) -> Word {
        *self
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}

/// Struct used to define the storage proof
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageProof {
    /// Storage key
    pub key: U256,
    /// Storage Value
    pub value: U256,
    /// Storage proof: rlp-encoded trie nodes from root to value.
    pub proof: Vec<Bytes>,
}

/// Struct used to define the result of `eth_getProof` call
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP1186ProofResponse {
    /// Account address
    pub address: Address,
    /// The balance of the account
    pub balance: U256,
    /// The hash of the code of the account
    pub code_hash: H256,
    /// The nonce of the account
    pub nonce: U64,
    /// SHA3 of the StorageRoot
    pub storage_hash: H256,
    /// Array of rlp-serialized MerkleTree-Nodes
    pub account_proof: Vec<Bytes>,
    /// Array of storage-entries as requested
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
#[doc(hidden)]
struct GethExecStepInternal {
    pc: u64,
    op: OpcodeId,
    gas: u64,
    #[serde(default)]
    refund: u64,
    #[serde(rename = "gasCost")]
    gas_cost: u64,
    depth: u16,
    error: Option<String>,
    // stack is in hex 0x prefixed
    stack: Vec<DebugU256>,
    // memory is in chunks of 32 bytes, in hex
    #[serde(default)]
    memory: Vec<DebugU256>,
    // storage is hex -> hex
    #[serde(default)]
    storage: HashMap<DebugU256, DebugU256>,
}

/// The execution step type returned by geth RPC debug_trace* methods.
/// Corresponds to `StructLogRes` in `go-ethereum/internal/ethapi/api.go`.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[doc(hidden)]
pub struct GethExecStep {
    pub pc: u64,
    pub op: OpcodeId,
    pub gas: u64,
    pub gas_cost: u64,
    pub refund: u64,
    pub depth: u16,
    pub error: Option<String>,
    // stack is in hex 0x prefixed
    pub stack: Stack,
    // memory is in chunks of 32 bytes, in hex
    pub memory: Memory,
    // storage is hex -> hex
    pub storage: Storage,
}

impl Default for GethExecStep {
    fn default() -> Self {
        Self {
            pc: 0,
            op: OpcodeId::default(),
            gas: 0,
            gas_cost: 0,
            refund: 0,
            depth: 0,
            error: None,
            stack: Stack::new(),
            memory: Memory::new(),
            storage: Storage::empty(),
        }
    }
}

// Wrapper over u8 that provides formats the byte in hex for [`fmt::Debug`].
pub(crate) struct DebugByte(pub(crate) u8);

impl fmt::Debug for DebugByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:02x}", self.0))
    }
}

// Wrapper over Word reference that provides formats the word in hex for
// [`fmt::Debug`].
pub(crate) struct DebugWord<'a>(pub(crate) &'a Word);

impl<'a> fmt::Debug for DebugWord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

impl fmt::Debug for GethExecStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("pc", &format_args!("0x{:04x}", self.pc))
            .field("op", &self.op)
            .field("gas", &format_args!("{}", self.gas))
            .field("gas_cost", &format_args!("{}", self.gas_cost))
            .field("depth", &self.depth)
            .field("error", &self.error)
            .field("stack", &self.stack)
            .field("memory", &self.memory)
            .field("storage", &self.storage)
            .finish()
    }
}

impl<'de> Deserialize<'de> for GethExecStep {
    fn deserialize<D>(deserializer: D) -> Result<GethExecStep, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = GethExecStepInternal::deserialize(deserializer)?;
        Ok(Self {
            pc: s.pc,
            op: s.op,
            gas: s.gas,
            refund: s.refund,
            gas_cost: s.gas_cost,
            depth: s.depth,
            error: s.error,
            stack: Stack(s.stack.iter().map(|dw| dw.to_word()).collect::<Vec<Word>>()),
            memory: Memory::from(
                s.memory
                    .iter()
                    .map(|dw| dw.to_word())
                    .collect::<Vec<Word>>(),
            ),
            storage: Storage(
                s.storage
                    .iter()
                    .map(|(k, v)| (k.to_word(), v.to_word()))
                    .collect(),
            ),
        })
    }
}

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTraces(pub Vec<ResultGethExecTrace>);

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTrace {
    pub result: GethExecTrace,
}

/// The execution trace type returned by geth RPC debug_trace* methods.
/// Corresponds to `ExecutionResult` in `go-ethereum/internal/ethapi/api.go`.
/// The deserialization truncates the memory of each step in `struct_logs` to
/// the memory size before the expansion, so that it corresponds to the memory
/// before the step is executed.
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct GethExecTrace {
    /// Used gas
    pub gas: u64,
    /// True when the transaction has failed.
    pub failed: bool,
    /// Return value of execution which is a hex encoded byte array
    #[serde(rename = "returnValue")]
    pub return_value: String,
    /// Vector of geth execution steps of the trace.
    #[serde(rename = "structLogs")]
    pub struct_logs: Vec<GethExecStep>,
    /// call trace from trace
    #[serde(rename = "callTrace", default)]
    pub call_trace: GethCallTrace,
}

///  type build to deal with Log
#[derive(Deserialize, Default, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct ReceiptLog {
    /// logs of transaction
    #[serde(default, rename = "logs")]
    pub logs: Vec<Log>,
}

impl ReceiptLog {
    /// from_single_log construct log from single log data
    pub fn from_single_log(
        address: Address,
        topics: Vec<H256>,
        data: Vec<u8>,
        block_hash: Option<H256>,
        block_number: Option<u64>,
        transaction_hash: Option<H256>,
        transaction_index: Option<u64>,
        log_index: Option<U256>,
        transaction_log_index: Option<U256>,
        log_type: Option<String>,
        removed: Option<bool>,
    ) -> Self {
        let mut receipt_log = ReceiptLog::default();
        receipt_log.logs.push(Log {
            address,
            topics,
            data: Bytes::from(data), // Bytes::from_static(data),
            block_hash,
            block_number: Some(U64::from(block_number.unwrap_or_default())),
            transaction_hash,
            transaction_index: Some(U64::from(transaction_index.unwrap_or_default())),
            log_index,
            transaction_log_index,
            log_type,
            removed,
        });
        receipt_log
    }
    /// check_data_valid check data from parsed log data
    pub fn check_data_valid(&self) -> () {
        for log in &self.logs {
            assert!(log.block_hash.is_some());
            assert!(log.block_number.is_some());
            assert!(log.transaction_hash.is_some());
            assert!(log.transaction_index.is_some());
            assert!(log.log_index.is_some());
            assert!(log.removed.is_some());
        }
    }
}

/// Used for FFI with Golang. Bytes in golang will be serialized as base64 by default.
pub mod base64 {
    use base64::{decode, encode};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// serialize bytes as base64
    pub fn serialize<S>(data: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        String::serialize(&encode(data), s)
    }

    /// deserialize base64 to bytes
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Log Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapReceiptLog {
    /// result in api result json
    pub result: ReceiptLog,
}

/// Transaction Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapTransaction {
    /// result in api result json
    pub result: Transaction,
}

/// Block Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapBlock {
    /// result in api result json
    pub result: Block<Transaction>,
}

/// ByteCode Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapByteCode {
    /// result in api result json
    pub result: String,
}

///Account Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapAccount {
    ///bytecode in each account
    pub bytecode: String,
    ///contract_addr in each account
    pub contract_addr: Address,
    /// storage in each account
    #[serde(default)]
    pub storage: HashMap<Word, Word>,
}
/// Accounts Wrapper in api result
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrapAccounts {
    /// result in api result json
    pub result: Vec<WrapAccount>,
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::Address::from_str(&$addr_hex).expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::Word::from_str_radix(&$word_hex, 16).expect("invalid hex Word")
    };
}

#[macro_export]
/// Create a [`Word`] to [`Word`] HashMap from pairs of hex strings.  Panics on
/// invalid input.
macro_rules! word_map {
    () => {
        std::collections::HashMap::new()
    };
    ($($key_hex:expr => $value_hex:expr),*) => {
        {
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_types::{memory::Memory, opcode_ids::OpcodeId, stack::Stack};

    use super::*;

    #[test]
    fn deserialize_geth_exec_trace2() {
        let trace_json = r#"
  {
    "gas": 26809,
    "failed": false,
    "returnValue": "",
    "structLogs": [
      {
        "pc": 0,
        "op": "PUSH1",
        "gas": 22705,
        "gasCost": 3,
        "refund": 0,
        "depth": 1,
        "stack": []
      },
      {
        "pc": 163,
        "op": "SLOAD",
        "gas": 5217,
        "gasCost": 2100,
        "refund": 0,
        "depth": 1,
        "stack": [
          "0x1003e2d2",
          "0x2a",
          "0x0"
        ],
        "storage": {
          "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000006f"
        },
        "memory": [
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000080"
        ]
      },
      {
        "pc": 189,
        "op": "KECCAK256",
        "gas": 178805,
        "gasCost": 42,
        "refund": 0,
        "depth": 1,
        "stack": [
            "0x3635c9adc5dea00000",
            "0x40",
            "0x0"
        ],
        "memory": [
            "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000"
        ]
      }
    ]
  }
        "#;
        let trace: GethExecTrace =
            serde_json::from_str(trace_json).expect("json-deserialize GethExecTrace");
        assert_eq!(
            trace,
            GethExecTrace {
                gas: 26809,
                failed: false,
                return_value: "".to_owned(),
                struct_logs: vec![
                    GethExecStep {
                        pc: 0,
                        op: OpcodeId::PUSH1,
                        gas: 22705,
                        refund: 0,
                        gas_cost: 3,
                        depth: 1,
                        error: None,
                        stack: Stack::new(),
                        storage: Storage(word_map!()),
                        memory: Memory::new(),
                    },
                    GethExecStep {
                        pc: 163,
                        op: OpcodeId::SLOAD,
                        gas: 5217,
                        refund: 0,
                        gas_cost: 2100,
                        depth: 1,
                        error: None,
                        stack: Stack(vec![word!("0x1003e2d2"), word!("0x2a"), word!("0x0")]),
                        storage: Storage(word_map!("0x0" => "0x6f")),
                        memory: Memory::from(vec![word!("0x0"), word!("0x0"), word!("0x080")]),
                    },
                    GethExecStep {
                        pc: 189,
                        op: OpcodeId::SHA3,
                        gas: 178805,
                        refund: 0,
                        gas_cost: 42,
                        depth: 1,
                        error: None,
                        stack: Stack(vec![
                            word!("0x3635c9adc5dea00000"),
                            word!("0x40"),
                            word!("0x0")
                        ]),
                        storage: Storage(word_map!()),
                        memory: Memory::from(vec![
                            word!(
                                "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000000000000000000000a0"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                        ]),
                    }
                ],
                call_trace: Default::default(),
            }
        );
    }
    #[test]
    fn deserialize_logs() {
        let logs_json = r#"
        {
            "transactionHash": "0x15bc89db9525912ddb289c647ec4b473dc3b326eec95308d4dcb2d8a98de1b99",
            "transactionIndex": "0x0",
            "blockHash": "0xee573172d327d8c99739cd936344bb5567be6e794c6c1863ae97520af81803fe",
            "blockNumber": "0x4",
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "cumulativeGasUsed": "0x8530",
            "gasUsed": "0x8530",
            "contractAddress": null,
            "logs": [
                {
                    "removed": false,
                    "logIndex": "0x0",
                    "transactionIndex": "0x0",
                    "transactionHash": "0x15bc89db9525912ddb289c647ec4b473dc3b326eec95308d4dcb2d8a98de1b99",
                    "blockHash": "0xee573172d327d8c99739cd936344bb5567be6e794c6c1863ae97520af81803fe",
                    "blockNumber": "0x4",
                    "address": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                    "data": "0x000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000674041ba",
                    "topics": [
                        "0xbf2ed60bd5b5965d685680c01195c9514e4382e28e3a5a2d2d5244bf59411b93"
                    ]
                }
            ],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000004000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000",
            "type": "0x2",
            "status": "0x1",
            "effectiveGasPrice": "0x23281169"
        }       
        "#;
        let logs: ReceiptLog =
            serde_json::from_str(logs_json).expect("json-deserialize ReceiptLog");
        assert_eq!(
            logs.logs,
            vec![Log {
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
        )
    }
}

#[cfg(test)]
mod eth_types_test {
    use std::str::FromStr;

    use crate::{Error, Word};

    use super::*;

    #[test]
    fn address() {
        // Test from_str
        assert_eq!(
            Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );
        assert_eq!(
            Address::from_str("9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );

        // Test from_str Errors
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543")
            ),
            "Err(Invalid input length)",
        );
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543XY")
            ),
            "Err(Invalid character 'X' at position 38)",
        );

        // Test to_word
        assert_eq!(
            Address::from_str("0x0000000000000000000000000000000000000001")
                .unwrap()
                .to_word(),
            Word::from(1u32),
        )
    }

    #[test]
    fn word_bytes_serialization_trip() -> Result<(), Error> {
        let first_usize = 64536usize;
        // Parsing on both ways works.
        assert_eq!(
            Word::from_little_endian(&first_usize.to_le_bytes()),
            Word::from_big_endian(&first_usize.to_be_bytes())
        );
        let addr = Word::from_little_endian(&first_usize.to_le_bytes());
        assert_eq!(addr, Word::from(first_usize));

        // Little endian export
        let mut le_obtained_usize = [0u8; 32];
        addr.to_little_endian(&mut le_obtained_usize);
        let mut le_array = [0u8; 8];
        le_array.copy_from_slice(&le_obtained_usize[0..8]);

        // Big endian export
        let mut be_array = [0u8; 8];
        let be_obtained_usize = addr.to_be_bytes();
        be_array.copy_from_slice(&be_obtained_usize[24..32]);

        assert_eq!(first_usize, usize::from_le_bytes(le_array));
        assert_eq!(first_usize, usize::from_be_bytes(be_array));

        Ok(())
    }

    #[test]
    fn word_from_str() -> Result<(), Error> {
        let word_str = "000000000000000000000000000000000000000000000000000c849c24f39248";

        let word_from_u128 = Word::from(3523505890234952u128);
        let word_from_str = Word::from_str(word_str).unwrap();

        assert_eq!(word_from_u128, word_from_str);
        Ok(())
    }

    #[test]
    fn creation_tx_into_tx_req() -> Result<(), Error> {
        let tx = &geth_types::Transaction {
            to: None,
            ..Default::default()
        };

        let req: ethers_core::types::TransactionRequest = tx.into();
        assert_eq!(req.to, None);
        Ok(())
    }
}
