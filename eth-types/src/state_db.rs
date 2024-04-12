//! EVM state db struct, Storage of values during the transaction process
use crate::{Word, U256};
use std::collections::{BTreeMap, HashMap, HashSet};

/// pending storage traversal starting index
/// 表示一个区块里第一笔交易的下标，在pending中取值时，取值范围是[BLOCK_TX_BEGIN_IDX, current_tx_idx)
/// eg:
///     - tx_idx = 1, pending 存储 (addr, key1, 1) = 1;
///     - tx_idx = 3 时取值，应该查询tx_idx [1..3)的值，而不是只查询tx_idx = 2的值;
pub(crate) const BLOCK_TX_BEGIN_IDX: usize = 1;

/// 与is_warm相关的opcode:
///     - sstore (addr, key)
///     - sload (addr, key)
///     - extcodecopy (addr)
///     - balance (addr)
///     - extcodesize (addr)
///     - extcodehash (addr)
///     - call,callcode,delegatecall,staticcall (addr)
///     - selfdestruct (addr)
///     - ErrorOOGAccountAccess (balance，extcodesize，extcodehash有关) (addr)
///     - ErrorOOGCall(call,callcode,delegatecall,staticcall) (addr)
///     - ErrorOOGMemoryCopy(extcodecopy) (addr)

/// state db for EVM
#[derive(Debug, Clone, Default)]
pub struct StateDB {
    /// key is address -- is_warm (生命周期是交易级别，影响的是一笔交易内的数据)
    /// is_warm在一笔交易中初次被访问时应该false，之后会被写为true
    pub access_list: HashSet<Word>,
    /// key is (address, slot) -- is_warm (生命周期是交易级别，影响的是一笔交易内的数据)
    /// is_warm在一笔交易中初次被访问时应该false，之后会被写为true
    /// 向lot_access_list中插入新的数据时, 会同时向该address插入access_list
    pub slot_access_list: HashSet<(Word, U256)>,
    /// key is (address, slot) -- value_prev (生命周期是交易级别，影响的是一笔交易内的数据)
    /// 同一笔交易，上一次sstore opcode写入的值
    pub dirty_storage: HashMap<(Word, U256), U256>,
    /// pending key is (address, slot, tx_idx) -- committed_value in pending (生命周期是交易级别，会因为上一笔交易的改变而改变)
    /// 上一笔交易，最后一次sstore对某个key写入的值
    pub pending_storage: BTreeMap<(Word, U256, usize), U256>,
    /// original key is (address, slot) -- committed_value in original (生命周期是区块级别，对于一个区块内的所有交易都是一样的)
    /// tx_idx == 1
    /// 同一个区块，上一个区块对应key的value，即已经提交的值，对于当前区块该值不会发生变化
    pub original_storage: HashMap<(Word, U256), U256>,
}

impl StateDB {
    /// new state db
    pub fn new() -> Self {
        Self {
            access_list: HashSet::new(),
            slot_access_list: HashSet::new(),
            dirty_storage: HashMap::new(),
            pending_storage: BTreeMap::new(),
            original_storage: HashMap::new(),
        }
    }
    /// Reset status after transaction execution
    pub fn reset_tx(&mut self) {
        self.access_list = HashSet::new();
        self.slot_access_list = HashSet::new();
        self.dirty_storage = HashMap::new();
    }

    /// check if address is in access list
    pub fn address_in_access_list(&self, address: &Word) -> bool {
        self.access_list.contains(address)
    }

    /// insert address into access list
    pub fn insert_access_list(&mut self, address: Word) {
        self.access_list.insert(address);
    }

    /// check if slot is in access list, key is (address, slot)
    pub fn slot_in_access_list(&self, address: &Word, slot: &U256) -> bool {
        self.slot_access_list.contains(&(*address, *slot))
    }

    /// insert slot into access list
    pub fn insert_slot_access_list(&mut self, address: Word, slot: U256) {
        // 如果是slot这种形式，address必须在access_list里
        self.access_list.insert(address);
        self.slot_access_list.insert((address, slot));
    }

    /// insert dirty storage, key is (address, slot)
    pub fn insert_dirty_storage(&mut self, address: Word, slot: U256, value: U256) {
        self.dirty_storage.insert((address, slot), value);
    }

    /// get dirty storage, key is (address, slot)
    pub fn get_dirty_storage(&self, address: &Word, slot: &U256) -> Option<U256> {
        self.dirty_storage.get(&(*address, *slot)).cloned()
    }

    /// insert pending storage, key is (address, slot, tx_idx)
    pub fn insert_pending_storage(
        &mut self,
        address: Word,
        slot: U256,
        value: U256,
        tx_idx: usize,
    ) {
        self.pending_storage.insert((address, slot, tx_idx), value);
    }

    /// check pending storage, key is (address, slot, tx_idx), if exist return true
    pub fn check_pending_storage(&self, address: U256, slot: U256, tx_idx: usize) -> bool {
        self.pending_storage.contains_key(&(address, slot, tx_idx))
    }

    /// get pending storage, key is (address, slot, tx_idx)
    pub fn get_pending_storage(&self, address: &U256, slot: &U256, tx_idx: usize) -> Option<U256> {
        let range = self
            .pending_storage
            .range((*address, *slot, BLOCK_TX_BEGIN_IDX)..(*address, *slot, tx_idx));
        range.last().map(|(_, value)| value.clone())
    }

    /// insert original storage, key is (address, slot)
    pub fn insert_original_storage(&mut self, address: Word, slot: U256, value: U256) {
        self.original_storage.insert((address, slot), value);
    }

    /// get original storage, key is (address, slot)
    pub fn get_original_storage(&self, address: &Word, slot: &U256) -> Option<U256> {
        self.original_storage.get(&(*address, *slot)).cloned()
    }

    // todo slot remove
    // todo address remove
}
