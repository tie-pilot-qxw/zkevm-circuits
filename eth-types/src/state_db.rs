//! EVM state db struct, Storage of values during the transaction process
use crate::{Word, U256};
use std::collections::{HashMap, HashSet};

/// state db for EVM
#[derive(Debug, Clone, Default)]
pub struct StateDB {
    /// key is address -- is_warm (生命周期是交易级别，影响的是一笔交易内的数据)
    pub access_list: HashSet<Word>,
    /// key is (address, slot) -- is_warm (生命周期是交易级别，影响的是一笔交易内的数据)
    pub slot_access_list: HashSet<(Word, U256)>,
    /// key is (address, slot) -- value_prev (生命周期是交易级别，影响的是一笔交易内的数据)
    pub dirty_storage: HashMap<(Word, U256), U256>,
    /// pending key is (address, slot, tx_idx) -- committed_value in pending (生命周期是交易级别，会因为上一笔交易的改变而改变)
    pub pending_storage: HashMap<(Word, U256), (U256, usize)>,
    /// original key is (address, slot) -- committed_value in original (生命周期是区块级别，对于一个区块内的所有交易都是一样的)
    /// tx_idx == 0
    pub original_storage: HashMap<(Word, U256), U256>,
}

impl StateDB {
    /// new state db
    pub fn new() -> Self {
        Self {
            access_list: HashSet::new(),
            slot_access_list: HashSet::new(),
            dirty_storage: HashMap::new(),
            pending_storage: HashMap::new(),
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
        self.pending_storage
            .insert((address, slot), (value, tx_idx));
    }

    /// get pending storage, key is (address, slot, tx_idx)
    pub fn get_pending_storage(&self, address: &Word, slot: &U256, tx_idx: usize) -> Option<U256> {
        match self.pending_storage.get(&(*address, *slot)).cloned() {
            Some((value, value_tx_idx)) => {
                if value_tx_idx < tx_idx {
                    Some(value)
                } else {
                    None
                }
            }
            None => None,
        }
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
