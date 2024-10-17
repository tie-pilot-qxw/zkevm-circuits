// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{
    ARITHMETIC_COLUMN_WIDTH, ARITHMETIC_TINY_COLUMN_WIDTH, ARITHMETIC_TINY_START_IDX,
    BITWISE_COLUMN_START_IDX, BITWISE_COLUMN_WIDTH, BYTECODE_COLUMN_START_IDX,
    COPY_LOOKUP_COLUMN_CNT, DESCRIPTION_AUXILIARY, EXP_COLUMN_START_IDX, FIXED_COLUMN_START_IDX,
    FIXED_COLUMN_WIDTH, LOG_SELECTOR_COLUMN_START_IDX, MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH,
    NUM_VERS, PUBLIC_COLUMN_START_IDX, PUBLIC_COLUMN_WIDTH, STAMP_CNT_COLUMN_START_IDX,
    STATE_COLUMN_WIDTH, STORAGE_COLUMN_WIDTH,
};
use crate::execution::ExecutionState;
use crate::util::cal_valid_stack_pointer_range;
use crate::witness::{
    arithmetic, assign_or_panic, bitwise, copy, fixed, public, state, WitnessExecHelper,
};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::U256;
use gadgets::dynamic_selector::get_dynamic_selector_assignments;
use gadgets::simple_seletor::simple_selector_assign;
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
    /// whether the current transaction is a transaction to create a contract
    pub tx_is_create: U256,
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

impl Row {
    pub fn insert_exp_lookup(&mut self, base: U256, index: U256, power: U256) {
        let (expect_power, _) = base.overflowing_pow(index);
        assert_eq!(expect_power, power);
        let colum_values = [
            base >> 128,
            base.low_u128().into(),
            index >> 128,
            index.low_u128().into(),
            power >> 128,
            power.low_u128().into(),
        ];
        for i in 0..6 {
            assign_or_panic!(self[EXP_COLUMN_START_IDX + i], colum_values[i]);
        }
    }

    pub fn fill_versatile_with_values(&mut self, values: &[U256]) {
        for i in 0..NUM_VERS {
            assign_or_panic!(self[i], values[i]);
        }
    }

    /// insert_bitwise_lookup insert bitwise lookup ,5 columns in row prev(-2)
    /// originated from 10 col
    /// cnt = 2 can hold at most 4 bitwise operations (10 + 5*4)
    /// +---+-------+-------+-------+---------------------------------------------+
    /// |cnt| 8 col | 8 col | 8 col |              8 col                          |
    /// +---+-------+-------+-------+---------------------------------------------+
    /// | 2 | 10 col |      5*index    | TAG | ACC_0 | ACC_1 | ACC_2 | SUM_2 |2col|
    /// +---+-------+-------+-------+----------+
    pub fn insert_bitwise_lookups(&mut self, index: usize, bitwise_row: &bitwise::Row) {
        assert!(index <= 3);
        assert_eq!(self.cnt, 2.into());
        let column_values = [
            U256::from(bitwise_row.tag as u8),
            bitwise_row.acc_0,
            bitwise_row.acc_1,
            bitwise_row.acc_2,
            bitwise_row.sum_2,
        ];
        let start = BITWISE_COLUMN_START_IDX + BITWISE_COLUMN_WIDTH * index;
        for i in 0..BITWISE_COLUMN_WIDTH {
            assign_or_panic!(self[start + i], column_values[i]);
        }
        self.comments.extend([
            (
                format!("vers_{}", start),
                format!("tag:{:?}", bitwise_row.tag),
            ),
            (format!("vers_{}", start + 1), "acc_0".into()),
            (format!("vers_{}", start + 2), "acc_1".into()),
            (format!("vers_{}", start + 3), "acc_2".into()),
            (format!("vers_{}", start + 4), "sum_2".into()),
        ]);
    }
    pub fn insert_most_significant_byte_len_lookups(
        &mut self,
        index: usize,
        bitwise_row: &bitwise::Row,
    ) {
        assert!(index <= 3);
        assert_eq!(self.cnt, 2.into());
        let start = BITWISE_COLUMN_START_IDX + MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH * index;
        let column_values = [bitwise_row.acc_2, bitwise_row.index];
        for i in 0..MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH {
            assign_or_panic!(self[start + i], column_values[i]);
        }
        self.comments.extend([
            (format!("vers_{}", start), "acc_2".into()),
            (format!("vers_{}", start + 1), "index".into()),
        ]);
    }
    pub fn insert_state_lookups<const NUM_LOOKUP: usize>(
        &mut self,
        state_rows: [&state::Row; NUM_LOOKUP],
    ) {
        // this lookup must be in the row with this cnt
        assert!(NUM_LOOKUP <= 4);
        assert!(NUM_LOOKUP > 0);
        for (j, state_row) in state_rows.into_iter().enumerate() {
            assign_or_panic!(
                self[0 + j * STATE_COLUMN_WIDTH],
                (state_row.tag.unwrap_or_default() as u8).into()
            );
            assign_or_panic!(
                self[1 + j * STATE_COLUMN_WIDTH],
                state_row.stamp.unwrap_or_default()
            );
            assign_or_panic!(
                self[2 + j * STATE_COLUMN_WIDTH],
                state_row.value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[3 + j * STATE_COLUMN_WIDTH],
                state_row.value_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[4 + j * STATE_COLUMN_WIDTH],
                state_row.call_id_contract_addr.unwrap_or_default()
            );
            assign_or_panic!(
                self[5 + j * STATE_COLUMN_WIDTH],
                state_row.pointer_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[6 + j * STATE_COLUMN_WIDTH],
                state_row.pointer_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[7 + j * STATE_COLUMN_WIDTH],
                state_row.is_write.unwrap_or_default()
            );
            self.comments.extend([
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH),
                    format!("tag={:?}", state_row.tag),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 1),
                    "stamp".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 2),
                    "value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 3),
                    "value_lo".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 4),
                    "call_id".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 5),
                    "not used".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 6),
                    "stack pointer".into(),
                ),
                (
                    format!("vers_{}", j * STATE_COLUMN_WIDTH + 7),
                    "is_write: read=0, write=1".into(),
                ),
            ]);
        }
    }

    // insert returndata size in cnt =3 row , fill column ranging from 0 to 7
    pub fn insert_returndata_size_state_lookup(&mut self, state_row: &state::Row) {
        assert_eq!(self.cnt, 3.into());
        assign_or_panic!(self[0], (state_row.tag.unwrap_or_default() as u8).into());
        assign_or_panic!(self[1], state_row.stamp.unwrap_or_default());
        assign_or_panic!(self[2], state_row.value_hi.unwrap_or_default());
        assign_or_panic!(self[3], state_row.value_lo.unwrap_or_default());
        assign_or_panic!(self[4], state_row.call_id_contract_addr.unwrap_or_default());
        assign_or_panic!(self[5], state_row.pointer_hi.unwrap_or_default());
        assign_or_panic!(self[6], state_row.pointer_lo.unwrap_or_default());
        assign_or_panic!(self[7], state_row.is_write.unwrap_or_default());
        self.comments.extend([
            (format!("vers_{}", 0), format!("tag={:?}", state_row.tag)),
            (format!("vers_{}", 1), "stamp".into()),
            (format!("vers_{}", 2), "value_hi".into()),
            (format!("vers_{}", 3), "value_lo".into()),
            (format!("vers_{}", 4), "call_id".into()),
            (format!("vers_{}", 5), "not used".into()),
            (format!("vers_{}", 6), "stack pointer".into()),
            (format!("vers_{}", 7), "is_write: read=0, write=1".into()),
        ]);
    }

    pub fn insert_storage_lookups<const NUM_LOOKUP: usize>(
        &mut self,
        state_rows: [&state::Row; NUM_LOOKUP],
    ) {
        assert!(NUM_LOOKUP < 3);
        assert!(NUM_LOOKUP > 0);
        for (j, state_row) in state_rows.into_iter().enumerate() {
            assign_or_panic!(
                self[0 + j * STORAGE_COLUMN_WIDTH],
                (state_row.tag.unwrap_or_default() as u8).into()
            );
            assign_or_panic!(
                self[1 + j * STORAGE_COLUMN_WIDTH],
                state_row.stamp.unwrap_or_default()
            );
            assign_or_panic!(
                self[2 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[3 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[4 + j * STORAGE_COLUMN_WIDTH],
                state_row.call_id_contract_addr.unwrap_or_default()
            );
            assign_or_panic!(
                self[5 + j * STORAGE_COLUMN_WIDTH],
                state_row.pointer_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[6 + j * STORAGE_COLUMN_WIDTH],
                state_row.pointer_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[7 + j * STORAGE_COLUMN_WIDTH],
                state_row.is_write.unwrap_or_default()
            );
            assign_or_panic!(
                self[8 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_pre_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[9 + j * STORAGE_COLUMN_WIDTH],
                state_row.value_pre_lo.unwrap_or_default()
            );
            assign_or_panic!(
                self[10 + j * STORAGE_COLUMN_WIDTH],
                state_row.committed_value_hi.unwrap_or_default()
            );
            assign_or_panic!(
                self[11 + j * STORAGE_COLUMN_WIDTH],
                state_row.committed_value_lo.unwrap_or_default()
            );
            self.comments.extend([
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH),
                    format!("tag={:?}", state_row.tag),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 1),
                    "stamp".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 2),
                    "value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 3),
                    "value_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 4),
                    "call_id".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 5),
                    "key_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 6),
                    "key_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 7),
                    "is_write: read=0, write=1".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 8),
                    "value_pre_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 9),
                    "value_pre_lo".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 10),
                    "committed_value_hi".into(),
                ),
                (
                    format!("vers_{}", j * STORAGE_COLUMN_WIDTH + 11),
                    "committed_value_lo".into(),
                ),
            ]);
        }
    }
    /// insert_stamp_cnt_lookups, include tag and cnt of state, tag always be EndPadding
    pub fn insert_stamp_cnt_lookups(&mut self, cnt: U256) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        assign_or_panic!(
            self[STAMP_CNT_COLUMN_START_IDX],
            U256::from(state::Tag::EndPadding as u8)
        );
        assign_or_panic!(self[STAMP_CNT_COLUMN_START_IDX + 1], cnt);

        #[rustfmt::skip]
		self.comments.extend([
			("vers_0".into(), "tag=EndPadding".into()),
			("vers_1".into(), "cnt".into()),
		]);
    }

    /// We can skip the constraint by setting code_addr to 0
    pub fn insert_bytecode_full_lookup(
        &mut self,
        pc: u64,
        opcode: OpcodeId,
        code_addr: U256,
        push_value: Option<U256>,
        not_code: bool,
    ) {
        // this lookup must be in the row with this cnt
        assert_eq!(self.cnt, 1.into());
        for (i, value) in (0..8).zip([
            code_addr,
            pc.into(),
            opcode.as_u8().into(),
            (not_code as u8).into(),
            push_value.map_or(U256::zero(), |x| (x >> 128)),
            push_value.map_or(U256::zero(), |x| (x.low_u128().into())),
            opcode.data_len().into(),
            (opcode.is_push_with_data() as u8).into(),
        ]) {
            assign_or_panic!(self[BYTECODE_COLUMN_START_IDX + i], value);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", 24), "code_addr".into()),
			(format!("vers_{}", 25), "pc".into()),
			(format!("vers_{}", 26), format!("opcode={}", opcode)),
			(format!("vers_{}", 27), "non_code".into()),
			(format!("vers_{}", 28), "push_value_hi".into()),
			(format!("vers_{}", 29), "push_value_lo".into()),
			(format!("vers_{}", 30), "X for PUSHX".into()),
			(format!("vers_{}", 31), "is_push".into()),
		]);
    }

    pub fn insert_fixed_lookup(&mut self, tag: fixed::Tag, values: Vec<U256>, index: usize) {
        // index must be 0~1
        assert!(index < 2);
        assert!(values.len() == 3);
        let start_idx = FIXED_COLUMN_START_IDX + index * FIXED_COLUMN_WIDTH;

        assign_or_panic!(self[start_idx], (tag as u8).into());
        assign_or_panic!(self[start_idx + 1], values[0]);
        assign_or_panic!(self[start_idx + 2], values[1]);
        assign_or_panic!(self[start_idx + 3], values[2]);

        self.comments.extend([
            (format!("vers_{}", start_idx), "fixed tag".into()),
            (format!("vers_{}", start_idx + 1), "value_0".into()),
            (format!("vers_{}", start_idx + 2), "value_1".into()),
            (format!("vers_{}", start_idx + 3), "value_2".into()),
        ]);
    }

    /// insert ConstantGasCost, StackPointerRange lookup.
    pub fn insert_fixed_lookup_opcode(&mut self, tag: fixed::Tag, op: OpcodeId, index: usize) {
        let (value_1, value_2) = match tag {
            fixed::Tag::ConstantGasCost => (op.constant_gas_cost().into(), 0.into()),
            fixed::Tag::StackPointerRange => {
                let (min_stack_pointer, max_stack_pointer) = cal_valid_stack_pointer_range(&op);
                (min_stack_pointer.into(), max_stack_pointer.into())
            }
            _ => panic!("not supported currently"),
        };
        self.insert_fixed_lookup(tag, vec![(op.as_u8()).into(), value_1, value_2], index);
    }

    pub fn insert_arithmetic_tiny_lookup(
        &mut self,
        index: usize,
        arith_entries: &[arithmetic::Row],
    ) {
        // in memory gas cost, arithmetic lookup needs to be placed on the cnt=1
        // assert_eq!(self.cnt, 2.into());
        assert!(index < 6);
        let arith_row = &arith_entries[arith_entries.len() - 1];
        let column_values = [
            arith_row.operand_0_hi,
            arith_row.operand_0_lo,
            arith_row.operand_1_hi,
            arith_row.operand_1_lo,
            (arith_row.tag as u8).into(),
        ];
        let offset = ARITHMETIC_TINY_START_IDX + index * ARITHMETIC_TINY_COLUMN_WIDTH;

        for i in 0..ARITHMETIC_TINY_COLUMN_WIDTH {
            assign_or_panic!(self[offset + i], column_values[i]);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", offset + 4), format!("arithmetic tag={:?}", arith_row.tag)),
		]);

        match arith_entries[0].tag {
            arithmetic::Tag::U64Overflow => {
                self.comments.extend([
                    (format!("vers_{}", offset), "value hi".into()),
                    (format!("vers_{}", offset + 1), "value lo".into()),
                    (format!("vers_{}", offset + 2), "w".into()),
                    (format!("vers_{}", offset + 3), "w_inv".into()),
                ]);
            }
            arithmetic::Tag::MemoryExpansion => {
                self.comments.extend([
                    (format!("vers_{}", offset), "offset".into()),
                    (format!("vers_{}", offset + 1), "memory_chunk_prev".into()),
                    (format!("vers_{}", offset + 2), "expansion_tag".into()),
                    (format!("vers_{}", offset + 3), "access_memory_size".into()),
                ]);
            }
            arithmetic::Tag::U64Div => {
                self.comments.extend([
                    (format!("vers_{}", offset), "numerator".into()),
                    (format!("vers_{}", offset + 1), "denominator".into()),
                    (format!("vers_{}", offset + 2), "quotient".into()),
                    (format!("vers_{}", offset + 3), "remainder".into()),
                ]);
            }
            _ => (),
        }
    }

    /// insert arithmetic_lookup insert arithmetic lookup, 9 columns in row prev(-2)
    /// row cnt = 2 can hold at most 3 arithmetic operations, 3 * 9 = 27
    /// +---+-------+-------+-------+-----+
    /// |cnt| 9 col | 9 col | 9 col |5 col|
    /// +---+-------+-------+-------+-----+
    /// | 2 | arith0|arith1 | arith2|     |
    /// +---+-------+-------+-------+-----+
    pub fn insert_arithmetic_lookup(&mut self, index: usize, arithmetic: &[arithmetic::Row]) {
        // this lookup must be in the row with this cnt
        assert!(index < 3);
        let len = arithmetic.len();
        assert!(len >= 2);
        let row_1 = &arithmetic[len - 2];
        let row_0 = &arithmetic[len - 1];
        let column_values = [
            row_0.operand_0_hi,
            row_0.operand_0_lo,
            row_0.operand_1_hi,
            row_0.operand_1_lo,
            row_1.operand_0_hi,
            row_1.operand_0_lo,
            row_1.operand_1_hi,
            row_1.operand_1_lo,
            (row_0.tag as u8).into(),
        ];
        let column_offset = index * ARITHMETIC_COLUMN_WIDTH;
        for i in 0..ARITHMETIC_COLUMN_WIDTH {
            assign_or_panic!(self[i + column_offset], column_values[i]);
        }
        #[rustfmt::skip]
		self.comments.extend([
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH), "arithmetic operand 0 hi".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 1), "arithmetic operand 0 lo".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 2), "arithmetic operand 1 hi".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 3), "arithmetic operand 1 lo".into()),
			(format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 8), format!("arithmetic tag={:?}", row_0.tag)),
		]);
        match row_0.tag {
            arithmetic::Tag::Add => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        "arithmetic sum hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        "arithmetic sum lo".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Addmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        format!("arithmetic operand modulus hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        format!("arithmetic operand modulus lo"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        format!("arithmetic remainder hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        format!("arithmetic remainder lo"),
                    ),
                ]);
            }
            arithmetic::Tag::Sub => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                        "arithmetic difference hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                        "arithmetic difference lo".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        "arithmetic carry hi".into(),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        "arithmetic carry lo".into(),
                    ),
                ]);
            }
            arithmetic::Tag::Mulmod => {
                self.comments.extend([
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                        format!("arithmetic r hi"),
                    ),
                    (
                        format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                        format!("arithmetic r lo"),
                    ),
                ]);
            }
            arithmetic::Tag::DivMod | arithmetic::Tag::SdivSmod => self.comments.extend([
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                    "arithmetic quotient hi".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                    "arithmetic quotient lo".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                    "arithmetic remainder hi".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                    "arithmetic remainder lo".into(),
                ),
            ]),
            arithmetic::Tag::Length => self.comments.extend([
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 4),
                    "arithmetic real_len".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 5),
                    "arithmetic zero_len".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 6),
                    "arithmetic real_len_is_zero".into(),
                ),
                (
                    format!("vers_{}", index * ARITHMETIC_COLUMN_WIDTH + 7),
                    "arithmetic zero_len_is_zero".into(),
                ),
            ]),
            _ => (),
        };
    }

    // insert_public_lookup insert public lookup ,6 columns
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub fn insert_public_lookup(&mut self, index: usize, public_row: &public::Row) {
        let column_values = [
            (public_row.tag as u8).into(),
            public_row.block_tx_idx.unwrap_or_default(),
            public_row.value_0.unwrap_or_default(),
            public_row.value_1.unwrap_or_default(),
            public_row.value_2.unwrap_or_default(),
            public_row.value_3.unwrap_or_default(),
        ];
        let start_idx = PUBLIC_COLUMN_START_IDX - index * PUBLIC_COLUMN_WIDTH;
        for i in 0..PUBLIC_COLUMN_WIDTH {
            assign_or_panic!(self[start_idx + i], column_values[i]);
        }
        let comments = vec![
            (
                format!("vers_{}", start_idx),
                format!("tag={:?}", public_row.tag),
            ),
            (format!("vers_{}", start_idx + 1), "block_tx_idx".into()),
            (format!("vers_{}", start_idx + 2), "value_0".into()),
            (format!("vers_{}", start_idx + 3), "value_1".into()),
            (format!("vers_{}", start_idx + 4), "value_2".into()),
            (format!("vers_{}", start_idx + 5), "value_3".into()),
        ];
        self.comments.extend(comments);
    }

    pub fn insert_copy_lookup(&mut self, index: usize, copy: &copy::Row) {
        // in row 2
        assert_eq!(self.cnt, 2.into());
        // max 2
        assert!(index < 2);
        let copy_values = vec![
            (copy.src_type as u8).into(),
            copy.src_id,
            copy.src_pointer,
            copy.src_stamp,
            (copy.dst_type as u8).into(),
            copy.dst_id,
            copy.dst_pointer,
            copy.dst_stamp,
            copy.cnt,
            copy.len,
            copy.acc,
        ];
        for i in 0..COPY_LOOKUP_COLUMN_CNT {
            assign_or_panic!(self[i + index * COPY_LOOKUP_COLUMN_CNT], copy_values[i]);
        }

        let comments = vec![
            // copy comment
            (
                format!("vers_{}", 0 + index * COPY_LOOKUP_COLUMN_CNT),
                format!("src_type={:?}", copy.src_type),
            ),
            (
                format!("vers_{}", 1 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_id".into(),
            ),
            (
                format!("vers_{}", 2 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_pointer".into(),
            ),
            (
                format!("vers_{}", 3 + index * COPY_LOOKUP_COLUMN_CNT),
                "src_stamp".into(),
            ),
            (
                format!("vers_{}", 4 + index * COPY_LOOKUP_COLUMN_CNT),
                format!("dst_type={:?}", copy.dst_type),
            ),
            (
                format!("vers_{}", 5 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_id".into(),
            ),
            (
                format!("vers_{}", 6 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_pointer".into(),
            ),
            (
                format!("vers_{}", 7 + index * COPY_LOOKUP_COLUMN_CNT),
                "dst_stamp".into(),
            ),
            (
                format!("vers_{}", 8 + index * COPY_LOOKUP_COLUMN_CNT),
                "cnt".into(),
            ),
            (
                format!("vers_{}", 9 + index * COPY_LOOKUP_COLUMN_CNT),
                "len".into(),
            ),
            (
                format!("vers_{}", 10 + index * COPY_LOOKUP_COLUMN_CNT),
                "acc".into(),
            ),
        ];
        self.comments.extend(comments);
    }

    pub fn insert_log_left_selector(&mut self, log_left: usize) {
        assert_eq!(self.cnt, 1.into());
        simple_selector_assign(
            self,
            [
                LOG_SELECTOR_COLUMN_START_IDX + 4,
                LOG_SELECTOR_COLUMN_START_IDX + 3,
                LOG_SELECTOR_COLUMN_START_IDX + 2,
                LOG_SELECTOR_COLUMN_START_IDX + 1,
                LOG_SELECTOR_COLUMN_START_IDX,
            ],
            log_left,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        self.comments.extend([
            ("vers_8".into(), "LOG_LEFT_4 Selector (0/1)".into()),
            ("vers_9".into(), "LOG_LEFT_3 Selector (0/1)".into()),
            ("vers_10".into(), "LOG_LEFT_2 Selector (0/1)".into()),
            ("vers_11".into(), "LOG_LEFT_1 Selector (0/1)".into()),
            ("vers_12".into(), "LOG_LEFT_0 Selector (0/1)".into()),
        ]);
    }
}

impl ExecutionState {
    pub fn into_exec_state_core_row(
        self,
        trace: &GethExecStep,
        current_state: &WitnessExecHelper,
        num_hi: usize,
        num_lo: usize,
    ) -> Row {
        let state = self as usize;
        assert!(
            state < num_hi * num_lo,
            "state index {} >= selector size {} * {}",
            state,
            num_hi,
            num_lo
        );
        let (selector_hi, selector_lo) = get_dynamic_selector_assignments(state, num_hi, num_lo);
        let mut row = current_state.get_core_row_without_versatile(&trace, 0);
        row.exec_state = Some(self);

        let memory_chunk = match self {
            ExecutionState::CALL_1 | ExecutionState::CALL_2 | ExecutionState::CALL_3 => {
                current_state.memory_chunk_prev
            }
            _ => current_state.memory_chunk,
        };

        for (i, value) in
            (0..NUM_VERS)
                .into_iter()
                .zip(selector_hi.into_iter().chain(selector_lo).chain([
                    current_state.state_stamp,
                    current_state.stack_pointer as u64,
                    current_state.log_stamp,
                    current_state.gas_left,
                    trace.refund,
                    memory_chunk,
                    current_state.read_only,
                ]))
        {
            assign_or_panic!(row[i], value.into());
        }
        for i in 0..num_hi {
            row.comments
                .insert(format!("vers_{}", i), format!("dynamic selector hi {}", i));
        }
        for i in 0..num_lo {
            row.comments.insert(
                format!("vers_{}", num_hi + i),
                format!("dynamic selector lo {}", i),
            );
        }
        for (i, text) in DESCRIPTION_AUXILIARY.iter().enumerate() {
            row.comments
                .insert(format!("vers_{}", num_hi + num_lo + i), text.to_string());
        }
        row
    }
}
