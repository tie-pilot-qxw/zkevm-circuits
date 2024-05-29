use crate::execution::ExecutionState;
use eth_types::evm_types::OpcodeId;
use eth_types::U256;
use serde::Serialize;
use std::collections::HashMap;
use std::ops::{Index, IndexMut};

/// core row has a few single-purpose columns (tx_idx, call_id, code_addr, pc, opcode, cnt)
/// and 32 versatile columns
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    // the following columns are single purpose, non-versatile
    /// block index, the index of the block in the chunk, repeated for rows in one block
    pub block_idx: U256,
    /// transaction index, the index inside the block, repeated for rows in one transaction
    pub tx_idx: U256,
    /// call id, unique for each call, repeated for rows in one execution state
    pub call_id: U256,
    /// contract code address, repeated for rows in one execution state
    pub code_addr: U256,
    /// program counter, repeated for rows in one execution state
    pub pc: U256,
    /// the opcode, repeated for rows in one execution state
    pub opcode: OpcodeId,
    /// row counter, decremented for rows in one execution state
    pub cnt: U256,
    // show the execution state to be human-readable, no used in circuit
    pub exec_state: Option<ExecutionState>,
    /// versatile columns that serve multiple purposes
    pub vers_0: Option<U256>,
    pub vers_1: Option<U256>,
    pub vers_2: Option<U256>,
    pub vers_3: Option<U256>,
    pub vers_4: Option<U256>,
    pub vers_5: Option<U256>,
    pub vers_6: Option<U256>,
    pub vers_7: Option<U256>,
    pub vers_8: Option<U256>,
    pub vers_9: Option<U256>,
    pub vers_10: Option<U256>,
    pub vers_11: Option<U256>,
    pub vers_12: Option<U256>,
    pub vers_13: Option<U256>,
    pub vers_14: Option<U256>,
    pub vers_15: Option<U256>,
    pub vers_16: Option<U256>,
    pub vers_17: Option<U256>,
    pub vers_18: Option<U256>,
    pub vers_19: Option<U256>,
    pub vers_20: Option<U256>,
    pub vers_21: Option<U256>,
    pub vers_22: Option<U256>,
    pub vers_23: Option<U256>,
    pub vers_24: Option<U256>,
    pub vers_25: Option<U256>,
    pub vers_26: Option<U256>,
    pub vers_27: Option<U256>,
    pub vers_28: Option<U256>,
    pub vers_29: Option<U256>,
    pub vers_30: Option<U256>,
    pub vers_31: Option<U256>,
    // if the row contains keccak rlc values, keccak input is here
    pub keccak_input: Option<Vec<u8>>,
    /// comments to show in html table that explain the purpose of each cell
    #[serde(skip_serializing)]
    pub comments: HashMap<String, String>,
}

impl Index<usize> for Row {
    type Output = Option<U256>;
    fn index<'a>(&'a self, i: usize) -> &'a Option<U256> {
        match i {
            0 => &self.vers_0,
            1 => &self.vers_1,
            2 => &self.vers_2,
            3 => &self.vers_3,
            4 => &self.vers_4,
            5 => &self.vers_5,
            6 => &self.vers_6,
            7 => &self.vers_7,
            8 => &self.vers_8,
            9 => &self.vers_9,
            10 => &self.vers_10,
            11 => &self.vers_11,
            12 => &self.vers_12,
            13 => &self.vers_13,
            14 => &self.vers_14,
            15 => &self.vers_15,
            16 => &self.vers_16,
            17 => &self.vers_17,
            18 => &self.vers_18,
            19 => &self.vers_19,
            20 => &self.vers_20,
            21 => &self.vers_21,
            22 => &self.vers_22,
            23 => &self.vers_23,
            24 => &self.vers_24,
            25 => &self.vers_25,
            26 => &self.vers_26,
            27 => &self.vers_27,
            28 => &self.vers_28,
            29 => &self.vers_29,
            30 => &self.vers_30,
            31 => &self.vers_31,
            _ => panic!("core.vers index out of bound"),
        }
    }
}
impl IndexMut<usize> for Row {
    fn index_mut<'a>(&'a mut self, i: usize) -> &'a mut Option<U256> {
        match i {
            0 => &mut self.vers_0,
            1 => &mut self.vers_1,
            2 => &mut self.vers_2,
            3 => &mut self.vers_3,
            4 => &mut self.vers_4,
            5 => &mut self.vers_5,
            6 => &mut self.vers_6,
            7 => &mut self.vers_7,
            8 => &mut self.vers_8,
            9 => &mut self.vers_9,
            10 => &mut self.vers_10,
            11 => &mut self.vers_11,
            12 => &mut self.vers_12,
            13 => &mut self.vers_13,
            14 => &mut self.vers_14,
            15 => &mut self.vers_15,
            16 => &mut self.vers_16,
            17 => &mut self.vers_17,
            18 => &mut self.vers_18,
            19 => &mut self.vers_19,
            20 => &mut self.vers_20,
            21 => &mut self.vers_21,
            22 => &mut self.vers_22,
            23 => &mut self.vers_23,
            24 => &mut self.vers_24,
            25 => &mut self.vers_25,
            26 => &mut self.vers_26,
            27 => &mut self.vers_27,
            28 => &mut self.vers_28,
            29 => &mut self.vers_29,
            30 => &mut self.vers_30,
            31 => &mut self.vers_31,
            _ => panic!("core.vers index out of bound"),
        }
    }
}
