use crate::util::create_contract_addr_with_prefix;
use eth_types::geth_types::GethData;
use eth_types::{GethExecStep, StateDB, U256};
use std::collections::HashSet;

pub fn handle_sload(
    to: U256,
    step: &GethExecStep,
    state_db: &mut StateDB,
    first_access: &mut HashSet<(U256, U256)>,
) {
    for (key, value) in &step.storage.0 {
        if !first_access.contains(&(to, *key)) {
            state_db.insert_original_storage(to, *key, value.clone());
            first_access.insert((to, *key));
        }
    }
}

// 传入的tx_idx下标从1开始计数
pub fn handle_sstore(to: U256, step: &GethExecStep, state_db: &mut StateDB, tx_idx: usize) {
    for (key, value) in &step.storage.0 {
        if state_db.get_pending_storage(&to, key, tx_idx).is_none() {
            // 倒序遍历，如果同一笔交易里有两个sstore操作，并且他们的key元组相同，那么只保留第一次插入的值
            state_db.insert_pending_storage(to, *key, value.clone(), tx_idx);
        }
    }
}

pub fn extract_address_from_tx(geth_data: &GethData, index: usize) -> U256 {
    let tx = geth_data
        .eth_block
        .transactions
        .get(index)
        .expect("tx_idx out of bounds");
    let to = tx.to.map_or_else(
        || create_contract_addr_with_prefix(&tx),
        |to| to.as_bytes().into(),
    );
    to
}
