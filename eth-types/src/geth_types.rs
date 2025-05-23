//! Types needed for generating Ethereum traces

use crate::{
    keccak256,
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    AccessList, Address, Block, Bytes, Error, GethExecTrace, Hash, ReceiptLog, ToBigEndian,
    ToLittleEndian, ToWord, Word, U64,
};
use ethers_core::{
    types::{transaction::response, NameOrAddress, TransactionRequest},
    utils::get_contract_address,
};
use halo2_proofs::halo2curves::{group::ff::PrimeField, secp256k1};
use num::Integer;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;

/// Definition of all of the data related to an account.
#[serde_as]
#[derive(PartialEq, Eq, Debug, Default, Clone, Deserialize, Serialize)]
pub struct Account {
    /// Address
    pub address: Word, // extend address to Word, to let create-contract tx has special address
    /// Nonce.
    /// U64 type is required to serialize into proper hex with 0x prefix
    pub nonce: U64,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: Bytes,
    /// Storage
    #[serde(serialize_with = "serde_account_storage")]
    pub storage: HashMap<Word, Word>,
}

impl Account {
    /// Return if account is empty or not.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero()
            && self.balance.is_zero()
            && self.code.is_empty()
            && self.storage.is_empty()
    }
}

fn serde_account_storage<S: Serializer>(
    to_serialize: &HashMap<Word, Word>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    to_serialize
        .iter()
        .map(|(k, v)| (Hash::from(k.to_be_bytes()), Hash::from(v.to_be_bytes())))
        .collect::<HashMap<_, _>>()
        .serialize(serializer)
}

/// Definition of all of the constants related to an Ethereum block and
/// chain to be used as setup for the external tracer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants {
    /// coinbase
    pub coinbase: Address,
    /// time
    pub timestamp: Word,
    /// Block number
    /// U64 type is required to serialize into proper hex with 0x prefix
    pub number: U64,
    /// difficulty
    pub difficulty: Word,
    /// gas limit
    pub gas_limit: Word,
    /// base fee
    pub base_fee: Word,
}

impl<TX> TryFrom<&Block<TX>> for BlockConstants {
    type Error = Error;

    fn try_from(block: &Block<TX>) -> Result<Self, Self::Error> {
        Ok(Self {
            coinbase: block.author.ok_or(Error::IncompleteBlock)?,
            timestamp: block.timestamp,
            number: block.number.ok_or(Error::IncompleteBlock)?,
            difficulty: block.mix_hash.ok_or(Error::IncompleteBlock)?.to_word(),
            gas_limit: block.gas_limit,
            base_fee: block.base_fee_per_gas.ok_or(Error::IncompleteBlock)?,
        })
    }
}

impl BlockConstants {
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        coinbase: Address,
        timestamp: Word,
        number: U64,
        difficulty: Word,
        gas_limit: Word,
        base_fee: Word,
    ) -> BlockConstants {
        BlockConstants {
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            base_fee,
        }
    }
}

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Transaction {
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    /// Avoid direct read from this field. We set this field public to construct the struct
    pub to: Option<Address>,
    /// Transaction nonce
    /// U64 type is required to serialize into proper hex with 0x prefix
    pub nonce: U64,
    /// Gas Limit / Supplied gas
    /// U64 type is required to serialize into proper hex with 0x prefix
    pub gas_limit: U64,
    /// Transfered value
    pub value: Word,
    /// Gas Price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see
    /// Ethereum Contract ABI
    pub call_data: Bytes,
    /// Access list
    pub access_list: Option<AccessList>,

    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,
}

impl From<&Transaction> for crate::Transaction {
    fn from(tx: &Transaction) -> crate::Transaction {
        crate::Transaction {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce.to_word(),
            gas: tx.gas_limit.to_word(),
            value: tx.value,
            gas_price: Some(tx.gas_price),
            max_priority_fee_per_gas: Some(tx.gas_fee_cap),
            max_fee_per_gas: Some(tx.gas_tip_cap),
            input: tx.call_data.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.into(),
            r: tx.r,
            s: tx.s,
            ..Default::default()
        }
    }
}

impl From<&crate::Transaction> for Transaction {
    fn from(tx: &crate::Transaction) -> Transaction {
        Transaction {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce.as_u64().into(),
            gas_limit: tx.gas.as_u64().into(),
            value: tx.value,
            gas_price: tx.gas_price.unwrap_or_default(),
            gas_fee_cap: tx.max_priority_fee_per_gas.unwrap_or_default(),
            gas_tip_cap: tx.max_fee_per_gas.unwrap_or_default(),
            call_data: tx.input.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.as_u64(),
            r: tx.r,
            s: tx.s,
        }
    }
}

impl From<&Transaction> for TransactionRequest {
    fn from(tx: &Transaction) -> TransactionRequest {
        TransactionRequest {
            from: Some(tx.from),
            to: tx.to.map(NameOrAddress::Address),
            gas: Some(tx.gas_limit.to_word()),
            gas_price: Some(tx.gas_price),
            value: Some(tx.value),
            data: Some(tx.call_data.clone()),
            nonce: Some(tx.nonce.to_word()),
            ..Default::default()
        }
    }
}

impl Transaction {
    /// Return the SignData associated with this Transaction.
    pub fn sign_data(&self, chain_id: u64) -> Result<SignData, Error> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let sig_r = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_r_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let sig_s = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_s_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        // msg = rlp([nonce, gasPrice, gas, to, value, data, sig_v, r, s])
        let req: TransactionRequest = self.into();
        let msg = req.chain_id(chain_id).rlp();
        let msg_hash: [u8; 32] = keccak256(&msg);
        let v = self
            .v
            .checked_sub(35 + chain_id * 2)
            .ok_or(Error::Signature(libsecp256k1::Error::InvalidSignature))? as u8;
        let pk = recover_pk(v, &self.r, &self.s, &msg_hash)?;
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )?;
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg_hash,
        })
    }

    /// Compute call data gas cost from call data
    pub fn call_data_gas_cost(&self) -> u64 {
        self.call_data
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 })
    }

    /// Get the "to" address. If `to` is None then zero address
    pub fn to_or_zero(&self) -> Address {
        self.to.unwrap_or_default()
    }
    /// Get the "to" address. If `to` is None then compute contract address
    pub fn to_or_contract_addr(&self) -> Address {
        self.to
            .unwrap_or_else(|| get_contract_address(self.from, self.nonce.to_word()))
    }
    /// Determine if this transaction is a contract create transaction
    pub fn is_create(&self) -> bool {
        self.to.is_none()
    }

    /// Convert to transaction response
    pub fn to_response(
        &self,
        transaction_index: U64,
        chain_id: Word,
        block_number: U64,
    ) -> response::Transaction {
        response::Transaction {
            from: self.from,
            to: self.to,
            value: self.value,
            input: self.call_data.clone(),
            gas_price: Some(self.gas_price),
            access_list: self.access_list.clone(),
            nonce: self.nonce.to_word(),
            gas: self.gas_limit.to_word(),
            transaction_index: Some(transaction_index),
            r: self.r,
            s: self.s,
            v: U64::from(self.v),
            block_number: Some(block_number),
            chain_id: Some(chain_id),
            ..response::Transaction::default()
        }
    }
    /// Convinient method for gas limit
    pub fn gas(&self) -> u64 {
        self.gas_limit.as_u64()
    }
}

/// GethData is a type that contains all the information of a Ethereum block
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GethData {
    /// Block from geth
    #[serde(rename = "block")]
    pub eth_block: Block<crate::Transaction>,
    /// Execution Trace from geth
    #[serde(rename = "executionResults")]
    pub geth_traces: Vec<GethExecTrace>,
    /// Accounts
    pub accounts: Vec<Account>,
    /// Logs of transactions
    #[serde(default)]
    pub logs: Vec<ReceiptLog>,
}

/// ChunkData is a type that contains all the information of a chunk、
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChunkData {
    /// chain id
    #[serde(rename = "chainId")]
    pub chain_id: Word,
    /// history hashes contains most recent (256 + blok_num_in_chunk block) hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    #[serde(rename = "historyHashes")]
    pub history_hashes: Vec<Word>,
    /// all blocks in the chunk
    #[serde(rename = "gethData")]
    pub blocks: Vec<GethData>,
}
