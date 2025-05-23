// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod add_sub_mul_div_mod;
pub mod addmod;
pub mod and_or_xor;
pub mod balance;
pub mod begin_block;
pub mod begin_chunk;
pub mod begin_tx_1;
pub mod begin_tx_2;
pub mod begin_tx_3;
pub mod blockhash;
pub mod byte;
pub mod call_1;
pub mod call_2;
pub mod call_3;
pub mod call_4;
pub mod call_5;
pub mod call_6;
pub mod call_7;
pub mod call_context;
pub mod calldatacopy;
pub mod calldataload;
pub mod codecopy;
pub mod codesize;
pub mod dup;
pub mod end_block;
pub mod end_call_1;
pub mod end_call_2;
pub mod end_chunk;
pub mod end_padding;
pub mod end_tx;
pub mod error_invalid_jump;
pub mod error_invalid_opcode;
pub mod error_invalid_stack_pointer;
pub mod error_oog_account_access;
pub mod error_oog_constant;
pub mod error_oog_log;
pub mod exp;
pub mod extcodecopy;
pub mod extcodeinfo;
pub mod iszero_eq;
pub mod jump;
pub mod jumpdest;
pub mod jumpi;
pub mod keccak;
pub mod log_bytes;
pub mod log_gas;
pub mod log_topic;
pub mod log_topic_num_addr;
pub mod lt_gt_slt_sgt;
pub mod mcopy;
pub mod memory;
pub mod memory_copier_gas;
pub mod memory_gas;
pub mod mstore8;
pub mod mulmod;
pub mod not;
pub mod pop;
pub mod post_call_1;
pub mod post_call_2;
pub mod public_context;
pub mod pure_memory_gas;
pub mod push;
pub mod return_revert;
pub mod returndatacopy;
pub mod returndatasize;
pub mod sar_1;
pub mod sar_2;
pub mod sdiv_smod;
pub mod selfbalance;
pub mod shl_shr;
pub mod signextend;
pub mod status_info;
pub mod stop;
pub mod storage;
pub mod swap;
pub mod tstorage;
pub mod tx_context;
pub mod unsupported;

use std::collections::BTreeMap;

use crate::table::{
    extract_lookup_expression, ArithmeticTable, BitwiseTable, BytecodeTable, CopyTable, ExpTable,
    FixedTable, LookupEntry, PublicTable, StateTable, ANNOTATE_SEPARATOR,
};
use crate::witness::state::CallContextTag;
use crate::witness::{arithmetic, bitwise, WitnessExecHelper};
use crate::witness::{copy, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Error, Field, GethExecStep};
use gadgets::dynamic_selector::DynamicSelectorConfig;
use gadgets::is_zero_with_rotation::IsZeroWithRotationConfig;
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::SimpleSelector;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression, Selector, VirtualCells};
use halo2_proofs::poly::Rotation;
use serde::Serialize;
use strum::EnumCount;
use strum_macros::EnumCount as EnumCountMacro;

/// Get all execution gadgets by using this
macro_rules! get_every_execution_gadgets {
    () => {{
        vec![
            crate::execution::add_sub_mul_div_mod::new(),
            crate::execution::addmod::new(),
            crate::execution::and_or_xor::new(),
            crate::execution::begin_block::new(),
            crate::execution::begin_chunk::new(),
            crate::execution::begin_tx_1::new(),
            crate::execution::begin_tx_2::new(),
            crate::execution::begin_tx_3::new(),
            crate::execution::blockhash::new(),
            crate::execution::byte::new(),
            crate::execution::call_1::new(),
            crate::execution::call_2::new(),
            crate::execution::call_3::new(),
            crate::execution::call_4::new(),
            crate::execution::call_5::new(),
            crate::execution::call_6::new(),
            crate::execution::call_7::new(),
            crate::execution::post_call_1::new(),
            crate::execution::post_call_2::new(),
            crate::execution::call_context::new(),
            crate::execution::calldatacopy::new(),
            crate::execution::calldataload::new(),
            crate::execution::codecopy::new(),
            crate::execution::extcodeinfo::new(),
            crate::execution::codesize::new(),
            crate::execution::dup::new(),
            crate::execution::end_block::new(),
            crate::execution::end_chunk::new(),
            crate::execution::end_padding::new(),
            crate::execution::end_tx::new(),
            crate::execution::exp::new(),
            crate::execution::extcodecopy::new(),
            crate::execution::iszero_eq::new(),
            crate::execution::jump::new(),
            crate::execution::jumpdest::new(),
            crate::execution::tstorage::new(),
            crate::execution::mcopy::new(),
            crate::execution::jumpi::new(),
            crate::execution::keccak::new(),
            crate::execution::log_bytes::new(),
            crate::execution::log_topic::new(),
            crate::execution::log_topic_num_addr::new(),
            crate::execution::lt_gt_slt_sgt::new(),
            crate::execution::memory::new(),
            crate::execution::mstore8::new(),
            crate::execution::mulmod::new(),
            crate::execution::not::new(),
            crate::execution::pop::new(),
            crate::execution::public_context::new(),
            crate::execution::push::new(),
            crate::execution::return_revert::new(),
            crate::execution::returndatacopy::new(),
            crate::execution::returndatasize::new(),
            crate::execution::sar_1::new(),
            crate::execution::sar_2::new(),
            crate::execution::sdiv_smod::new(),
            crate::execution::selfbalance::new(),
            crate::execution::shl_shr::new(),
            crate::execution::signextend::new(),
            crate::execution::status_info::new(),
            crate::execution::stop::new(),
            crate::execution::storage::new(),
            crate::execution::swap::new(),
            crate::execution::tx_context::new(),
            crate::execution::memory_gas::new(),
            crate::execution::memory_copier_gas::new(),
            crate::execution::pure_memory_gas::new(),
            crate::execution::log_gas::new(),
            crate::execution::balance::new(),
            crate::execution::error_invalid_jump::new(),
            crate::execution::end_call_1::new(),
            crate::execution::end_call_2::new(),
            crate::execution::error_oog_account_access::new(),
            crate::execution::error_oog_constant::new(),
            crate::execution::unsupported::new(),
            crate::execution::error_oog_log::new(),
            crate::execution::error_invalid_opcode::new(),
            crate::execution::error_invalid_stack_pointer::new(),
        ]
    }};
}
use crate::constant::{
    self, ARITHMETIC_COLUMN_WIDTH, ARITHMETIC_TINY_COLUMN_WIDTH, ARITHMETIC_TINY_START_IDX,
    BITWISE_COLUMN_START_IDX, BITWISE_COLUMN_WIDTH, BYTECODE_COLUMN_START_IDX,
    COPY_LOOKUP_COLUMN_CNT, EXP_COLUMN_START_IDX, FIXED_COLUMN_START_IDX, FIXED_COLUMN_WIDTH,
    LOG_SELECTOR_COLUMN_START_IDX, MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH, PUBLIC_COLUMN_START_IDX,
    PUBLIC_COLUMN_WIDTH, STAMP_CNT_COLUMN_START_IDX, STATE_COLUMN_WIDTH, STORAGE_COLUMN_WIDTH,
};
use crate::constant::{NUM_VERS, PUBLIC_NUM_VALUES};
use crate::error::{ExecError, OogError};
use crate::util::ExpressionOutcome;
pub(crate) use get_every_execution_gadgets;

#[allow(unused)]
#[derive(Clone)]
pub(crate) struct ExecutionConfig<F, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> {
    /// only enable for BEGIN_CHUNK
    pub(crate) q_first_exec_state: Selector,
    pub(crate) q_enable: Selector,
    // witness column of block index
    pub(crate) block_idx: Column<Advice>,
    // witness column of transaction index
    pub(crate) tx_idx: Column<Advice>,
    /// whether the current transaction is a transaction to create a contract
    pub tx_is_create: Column<Advice>,
    // witness column of call id
    pub(crate) call_id: Column<Advice>,
    // witness column of contract address
    pub(crate) code_addr: Column<Advice>,
    // witness column of program counter
    pub(crate) pc: Column<Advice>,
    // witness columns of opcode
    pub(crate) opcode: Column<Advice>,
    // witness column of opcode counter
    pub(crate) cnt: Column<Advice>,
    // witness columns of 32 versatile purposes
    pub(crate) vers: [Column<Advice>; NUM_VERS],
    // IsZero chip for witness column cnt
    pub(crate) cnt_is_zero: IsZeroWithRotationConfig<F>,
    // Selector of execution state
    pub(crate) execution_state_selector:
        DynamicSelectorConfig<F, { ExecutionState::COUNT }, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    // Tables used for lookup
    pub(crate) bytecode_table: BytecodeTable<F>,
    pub(crate) state_table: StateTable,
    pub(crate) arithmetic_table: ArithmeticTable,
    pub(crate) copy_table: CopyTable,
    pub(crate) bitwise_table: BitwiseTable,
    pub(crate) public_table: PublicTable,
    pub(crate) fixed_table: FixedTable,
    pub(crate) exp_table: ExpTable,
}

// Columns in this struct should be used with Rotation::cur() and condition cnt_is_zero
#[derive(Clone)]
pub(crate) struct Auxiliary {
    /// State stamp (counter) at the end of the execution state
    pub(crate) state_stamp: Column<Advice>,
    /// Stack pointer at the end of the execution state
    pub(crate) stack_pointer: Column<Advice>,
    /// Log stamp (counter) at the end of the execution state
    pub(crate) log_stamp: Column<Advice>,
    /// Gas left at the end of the execution state
    pub(crate) gas_left: Column<Advice>,
    /// Refund at the end of the execution state
    pub(crate) refund: Column<Advice>,
    /// Memory usage in chunk at the end of the execution state
    pub(crate) memory_chunk: Column<Advice>,
    /// Read only indicator (0/1) at the end of the execution state
    pub(crate) read_only: Column<Advice>,
}

/// Outcome for `Auxiliary`. That is, we have constraint of `X_cur - X_prev - delta = 0` or `X_cur - to = 0`
#[derive(Clone)]
pub(crate) struct AuxiliaryOutcome<F> {
    /// Outcome of state stamp (counter) at the end of the execution state and the previous state
    pub(crate) state_stamp: ExpressionOutcome<F>,
    /// Outcome of stack pointer at the end of the execution state and the previous state
    pub(crate) stack_pointer: ExpressionOutcome<F>,
    /// Outcome of log stamp (counter) at the end of the execution state and the previous state
    pub(crate) log_stamp: ExpressionOutcome<F>,
    /// Outcome of gas left at the end of the execution state and the previous state
    pub(crate) gas_left: ExpressionOutcome<F>,
    /// Outcome of refund at the end of the execution state and the previous state
    pub(crate) refund: ExpressionOutcome<F>,
    /// Outcome of memory usage in chunk at the end of the execution state and the previous state
    pub(crate) memory_chunk: ExpressionOutcome<F>, // `memory_word_size = ceil(address/32) = floor((address + 31) / 32)`
    /// Outcome of read only indicator (0/1) at the end of the execution state and the previous state
    pub(crate) read_only: ExpressionOutcome<F>,
}

impl<F: Field> Default for AuxiliaryOutcome<F> {
    fn default() -> Self {
        Self {
            state_stamp: ExpressionOutcome::Delta(0.expr()),
            stack_pointer: ExpressionOutcome::Delta(0.expr()),
            log_stamp: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            memory_chunk: ExpressionOutcome::Delta(0.expr()),
            read_only: ExpressionOutcome::Delta(0.expr()),
        }
    }
}

/// Outcome for single-purpose (SP) columns in core circuit. That is, we have constraint of `X_next - X_cur - delta = 0` or `X_next - to = 0`
pub(crate) struct CoreSinglePurposeOutcome<F> {
    /// Delta of pc (program counter) at the next execution state and current execution state
    pub(crate) pc: ExpressionOutcome<F>,
    pub(crate) block_idx: ExpressionOutcome<F>,
    pub(crate) tx_idx: ExpressionOutcome<F>,
    pub(crate) tx_is_create: ExpressionOutcome<F>,
    pub(crate) call_id: ExpressionOutcome<F>,
    pub(crate) code_addr: ExpressionOutcome<F>,
}

impl<F: Field> Default for CoreSinglePurposeOutcome<F> {
    fn default() -> Self {
        Self {
            pc: ExpressionOutcome::Delta(0.expr()),
            block_idx: ExpressionOutcome::Delta(0.expr()),
            tx_idx: ExpressionOutcome::Delta(0.expr()),
            tx_is_create: ExpressionOutcome::Delta(0.expr()),
            call_id: ExpressionOutcome::Delta(0.expr()),
            code_addr: ExpressionOutcome::Delta(0.expr()),
        }
    }
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub(crate) fn get_exp_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (base, index, power) = (
            [
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX], Rotation::prev()),
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX + 1], Rotation::prev()),
            ],
            [
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX + 2], Rotation::prev()),
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX + 3], Rotation::prev()),
            ],
            [
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX + 4], Rotation::prev()),
                meta.query_advice(self.vers[EXP_COLUMN_START_IDX + 5], Rotation::prev()),
            ],
        );
        LookupEntry::Exp { base, index, power }
    }

    pub(crate) fn get_bitwise_lookup(
        &self,

        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        assert!(index <= 3);
        LookupEntry::Bitwise {
            tag: meta.query_advice(
                self.vers[BITWISE_COLUMN_START_IDX + index * BITWISE_COLUMN_WIDTH],
                Rotation(-2),
            ),
            acc: [
                meta.query_advice(
                    self.vers[BITWISE_COLUMN_START_IDX + index * BITWISE_COLUMN_WIDTH + 1],
                    Rotation(-2),
                ),
                meta.query_advice(
                    self.vers[BITWISE_COLUMN_START_IDX + index * BITWISE_COLUMN_WIDTH + 2],
                    Rotation(-2),
                ),
                meta.query_advice(
                    self.vers[BITWISE_COLUMN_START_IDX + index * BITWISE_COLUMN_WIDTH + 3],
                    Rotation(-2),
                ),
            ],
            sum_2: meta.query_advice(
                self.vers[BITWISE_COLUMN_START_IDX + index * BITWISE_COLUMN_WIDTH + 4],
                Rotation(-2),
            ),
        }
    }

    pub(crate) fn get_most_significant_byte_len_lookup(
        &self,

        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        assert!(index <= 3);
        LookupEntry::MostSignificantByteLen {
            acc_2: meta.query_advice(
                self.vers
                    [BITWISE_COLUMN_START_IDX + MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH * index],
                Rotation(-2),
            ),
            index: meta.query_advice(
                self.vers
                    [BITWISE_COLUMN_START_IDX + MOST_SIGNIFICANT_BYTE_LEN_COLUMN_WIDTH * index + 1],
                Rotation(-2),
            ),
        }
    }

    pub(crate) fn get_state_lookup_by_rotation(
        &self,
        meta: &mut VirtualCells<F>,
        at: Rotation,
        index: usize,
    ) -> LookupEntry<F> {
        assert!(index < 4);
        let (
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        ) = (
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 0], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 1], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 2], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 3], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 4], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 5], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 6], at),
            meta.query_advice(self.vers[index * STATE_COLUMN_WIDTH + 7], at),
        );
        LookupEntry::State {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        }
    }

    pub(crate) fn get_state_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        self.get_state_lookup_by_rotation(meta, Rotation::prev(), index)
    }

    pub(crate) fn get_returndata_size_state_lookup(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> LookupEntry<F> {
        let (
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        ) = (
            meta.query_advice(self.vers[0], Rotation(-3)),
            meta.query_advice(self.vers[1], Rotation(-3)),
            meta.query_advice(self.vers[2], Rotation(-3)),
            meta.query_advice(self.vers[3], Rotation(-3)),
            meta.query_advice(self.vers[4], Rotation(-3)),
            meta.query_advice(self.vers[5], Rotation(-3)),
            meta.query_advice(self.vers[6], Rotation(-3)),
            meta.query_advice(self.vers[7], Rotation(-3)),
        );
        LookupEntry::State {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        }
    }

    pub(crate) fn get_storage_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        num: usize,
        at: Rotation,
    ) -> LookupEntry<F> {
        assert!(num < 2);
        let (
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            key_hi,
            key_lo,
            is_write,
            value_pre_hi,
            value_pre_lo,
            committed_value_hi,
            committed_value_lo,
        ) = (
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 0], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 1], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 2], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 3], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 4], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 5], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 6], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 7], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 8], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 9], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 10], at),
            meta.query_advice(self.vers[num * STORAGE_COLUMN_WIDTH + 11], at),
        );
        LookupEntry::Storage {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            key_hi,
            key_lo,
            is_write,
            value_pre_hi,
            value_pre_lo,
            committed_value_hi,
            committed_value_lo,
        }
    }

    // insert_public_lookup insert public lookup ,6 columns
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub(crate) fn get_public_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        self.get_public_lookup_with_rotation(meta, index, Rotation(-2))
    }

    pub(crate) fn get_public_lookup_with_rotation(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
        at: Rotation,
    ) -> LookupEntry<F> {
        let start_idx = PUBLIC_COLUMN_START_IDX - index * PUBLIC_COLUMN_WIDTH;
        let (tag, block_tx_idx, value_0, value_1, value_2, value_3) = (
            meta.query_advice(self.vers[start_idx], at),
            meta.query_advice(self.vers[start_idx + 1], at),
            meta.query_advice(self.vers[start_idx + 2], at),
            meta.query_advice(self.vers[start_idx + 3], at),
            meta.query_advice(self.vers[start_idx + 4], at),
            meta.query_advice(self.vers[start_idx + 5], at),
        );

        let values = [value_0, value_1, value_2, value_3];
        LookupEntry::Public {
            tag,
            block_tx_idx,
            values,
        }
    }

    pub(crate) fn get_copy_constraints(
        &self,
        src_type: copy::Tag,
        src_id: Expression<F>,
        src_pointer: Expression<F>,
        src_stamp: Expression<F>,
        dst_type: copy::Tag,
        dst_id: Expression<F>,
        dst_pointer: Expression<F>,
        dst_stamp: Expression<F>,
        cnt: Option<Expression<F>>,
        len: Expression<F>,
        len_is_zero: Expression<F>,
        acc: Option<Expression<F>>,
        copy_lookup_entry: LookupEntry<F>,
    ) -> Vec<(String, Expression<F>)> {
        self.get_copy_constraints_with_src_dst_type(
            src_type.into(),
            src_type.as_u8().expr(),
            src_id,
            src_pointer,
            src_stamp,
            dst_type.into(),
            dst_type.as_u8().expr(),
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            len_is_zero,
            acc,
            copy_lookup_entry,
        )
    }

    pub(crate) fn get_copy_constraints_with_src_dst_type(
        &self,
        src_type: String,
        src_type_expr: Expression<F>,
        src_id: Expression<F>,
        src_pointer: Expression<F>,
        src_stamp: Expression<F>,
        dst_type: String,
        dst_type_expr: Expression<F>,
        dst_id: Expression<F>,
        dst_pointer: Expression<F>,
        dst_stamp: Expression<F>,
        cnt: Option<Expression<F>>,
        len: Expression<F>,
        len_is_zero: Expression<F>,
        acc: Option<Expression<F>>,
        copy_lookup_entry: LookupEntry<F>,
    ) -> Vec<(String, Expression<F>)> {
        assert_eq!(cnt.is_some(), acc.is_some());

        let (
            copy_lookup_src_type,
            copy_lookup_src_id,
            copy_lookup_src_pointer,
            copy_lookup_src_stamp,
            copy_lookup_dst_type,
            copy_lookup_dst_id,
            copy_lookup_dst_pointer,
            copy_lookup_dst_stamp,
            copy_lookup_cnt,
            copy_lookup_length,
            copy_lookup_acc,
        ) = extract_lookup_expression!(copy, copy_lookup_entry);

        let mut constraints = vec![];
        constraints.extend([
            (
                format!("src_type of copy is {:?}", src_type),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_type.clone() - src_type_expr)
                    + len_is_zero.clone() * copy_lookup_src_type,
            ),
            (
                "src_id of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_id.clone() - src_id)
                    + len_is_zero.clone() * copy_lookup_src_id,
            ),
            (
                "src_pointer of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_pointer.clone() - src_pointer)
                    + len_is_zero.clone() * copy_lookup_src_pointer,
            ),
            (
                "src_stamp of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_stamp.clone() - src_stamp)
                    + len_is_zero.clone() * copy_lookup_src_stamp,
            ),
            (
                format!("dst_type of copy is {:?}", dst_type),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_type.clone() - dst_type_expr)
                    + len_is_zero.clone() * copy_lookup_dst_type,
            ),
            (
                "dst_id of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_id.clone() - dst_id)
                    + len_is_zero.clone() * copy_lookup_dst_id,
            ),
            (
                "dst_pointer of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_pointer.clone() - dst_pointer)
                    + len_is_zero.clone() * copy_lookup_dst_pointer,
            ),
            (
                "dst_stamp of copy".into(),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_stamp.clone() - dst_stamp)
                    + len_is_zero.clone() * copy_lookup_dst_stamp,
            ),
            ("length of copy".into(), copy_lookup_length.expr() - len),
            (
                "cnt of copy = 0 if len = 0".into(),
                len_is_zero.clone() * copy_lookup_cnt.clone(),
            ),
            (
                "acc of copy = 0 if len = 0".into(),
                len_is_zero.clone() * copy_lookup_acc.clone(),
            ),
        ]);
        if let Some(cnt) = cnt {
            constraints.push((
                "cnt of copy = some value".into(),
                copy_lookup_cnt - cnt.clone(),
            ))
        }
        if let Some(acc) = acc {
            constraints.push((
                "acc of copy = some value".into(),
                copy_lookup_acc - acc.clone(),
            ))
        }
        constraints
    }

    ///generate copy lookup's constraints which are controlled by the selector (enabled when selector != 0.expr() and disabled when selector == 0.expr())
    pub(crate) fn get_copy_constraints_with_selector(
        &self,
        src_type: copy::Tag,
        src_id: Expression<F>,
        src_pointer: Expression<F>,
        src_stamp: Expression<F>,
        dst_type: copy::Tag,
        dst_id: Expression<F>,
        dst_pointer: Expression<F>,
        dst_stamp: Expression<F>,
        cnt: Option<Expression<F>>,
        len: Expression<F>,
        len_is_zero: Expression<F>,
        acc: Option<Expression<F>>,
        selector: Expression<F>,
        copy_lookup_entry: LookupEntry<F>,
    ) -> Vec<(String, Expression<F>)> {
        let constraints_raw = self.get_copy_constraints(
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            len_is_zero.clone(),
            acc,
            copy_lookup_entry.clone(),
        );

        let res: Vec<(String, Expression<F>)> = constraints_raw
            .into_iter()
            .map(|constraint| (constraint.0, selector.clone() * constraint.1))
            .collect();

        res
    }

    pub(crate) fn get_stack_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        stack_pointer_delta: Expression<F>, // compare to that of previous state
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary {
            state_stamp,
            stack_pointer,
            ..
        } = self.get_auxiliary();
        self.get_state_constraints(
            entry,
            index,
            (state::Tag::Stack as u8).expr(),
            meta.query_advice(self.call_id, Rotation::cur()),
            0.expr(),
            meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32))
                + stack_pointer_delta,
            meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                + index.expr(),
            (is_write as u8).expr(),
        )
    }

    pub(crate) fn get_read_value_constraints_by_call(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        prev_exec_state_row: usize,
        selector: &SimpleSelector<F, 3>,
        index: usize,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary {
            state_stamp,
            stack_pointer,
            ..
        } = self.get_auxiliary();
        let call_id = meta.query_advice(self.call_id, Rotation::cur());
        let stamp_expr = meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32));
        let stack_pointer_expr =
            meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32));
        let tag = selector.select(&[
            (state::Tag::Stack as u8).expr(),       // CALL
            (state::Tag::Memory as u8).expr(),      // STATICCALLL(state::Row::Default())
            (state::Tag::CallContext as u8).expr(), // DELEGATECALL
        ]);

        let call_id = selector.select(&[
            call_id.clone(), // CALL
            0.expr(),        // STATICCALL(state::Row::Default())
            call_id.clone(), // DELEGATECALL
        ]);

        let pointer_lo = selector.select(&[
            stack_pointer_expr - 2.expr(), // CALL （the position of value is -2）
            0.expr(),                      // STATICCALLL(state::Row::Default())
            (state::CallContextTag::Value as u8).expr(), // DELEGATECALL
        ]);

        let stamp = selector.select(&[
            stamp_expr.expr() + index.expr(),  // CALL
            0.expr(),                          // STATICCALLL(state::Row::Default())
            stamp_expr.clone() + index.expr(), // DELEGATECALL
        ]);

        self.get_state_constraints(
            entry,
            index,
            tag,
            call_id,
            0.expr(),
            pointer_lo,
            stamp,
            0.expr(),
        )
    }

    pub(crate) fn get_state_constraints(
        &self,
        entry: LookupEntry<F>,
        index: usize,
        tag: Expression<F>,
        call_id_or_contract_addr: Expression<F>,
        pointer_hi: Expression<F>,
        pointer_lo: Expression<F>,
        stamp: Expression<F>,
        is_write: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let (
            lookup_tag,
            lookup_stamp,
            _value_hi,
            _value_lo,
            call_id_contract_addr,
            lookup_pointer_hi,
            lookup_pointer_lo,
            lookup_is_write,
        ) = extract_lookup_expression!(state, entry);
        vec![
            (format!("state lookup tag[{}]", index), lookup_tag - tag),
            (
                format!("state stamp for state lookup[{}]", index),
                lookup_stamp - stamp,
            ),
            (
                format!("state lookup call id[{}]", index),
                call_id_contract_addr - call_id_or_contract_addr,
            ),
            (
                format!("state lookup pointer_hi[{}]", index),
                lookup_pointer_hi - pointer_hi,
            ),
            (
                format!("state lookup pointer_lo[{}]", index),
                lookup_pointer_lo - pointer_lo,
            ),
            (
                format!("state lookup is_write[{}]", index),
                lookup_is_write - is_write,
            ),
        ]
    }

    pub(crate) fn get_stack_constraints_with_state_default(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        stack_pointer_delta: Expression<F>, // compare to that of previous state
        state_stamp_delta: Expression<F>,
        is_default: Expression<F>,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary {
            state_stamp,
            stack_pointer,
            ..
        } = self.get_auxiliary();
        self.get_state_constraints(
            entry,
            index,
            is_default.clone() * 0.expr()
                + (1.expr() - is_default.clone()) * (state::Tag::Stack as u8).expr(),
            is_default.clone() * 0.expr()
                + (1.expr() - is_default.clone())
                    * meta.query_advice(self.call_id, Rotation::cur()),
            0.expr(),
            is_default.clone() * 0.expr()
                + (1.expr() - is_default.clone())
                    * (meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32))
                        + stack_pointer_delta),
            is_default.clone() * 0.expr()
                + (1.expr() - is_default.clone())
                    * (meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                        + state_stamp_delta),
            is_default.clone() * 0.expr()
                + (1.expr() - is_default.clone()) * (is_write as u8).expr(),
        )
    }

    pub(crate) fn get_memory_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        memory_pointer_lo: Expression<F>,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        self.get_state_constraints(
            entry,
            index,
            (state::Tag::Memory as u8).expr(),
            meta.query_advice(self.call_id, Rotation::cur()),
            0.expr(),
            memory_pointer_lo,
            meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                + index.expr(),
            (is_write as u8).expr(),
        )
    }

    pub(crate) fn get_lookup_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        lookup: LookupEntry<F>,
        condition: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let v: Vec<(Expression<F>, Expression<F>)> = match lookup {
            LookupEntry::BytecodeFull { .. } | LookupEntry::Bytecode { .. } => {
                self.bytecode_table.get_lookup_vector(meta, lookup)
            }
            LookupEntry::State { .. } | LookupEntry::Storage { .. } => {
                self.state_table.get_lookup_vector(meta, lookup)
            }
            LookupEntry::Public { .. } => self.public_table.get_lookup_vector(meta, lookup),
            LookupEntry::Bitwise { .. } | LookupEntry::MostSignificantByteLen { .. } => {
                self.bitwise_table.get_lookup_vector(meta, lookup)
            }
            LookupEntry::Copy { .. } => self.copy_table.get_lookup_vector(meta, lookup),
            LookupEntry::Arithmetic { .. }
            | LookupEntry::ArithmeticTiny { .. }
            | LookupEntry::ArithmeticShort { .. } => {
                self.arithmetic_table.get_lookup_vector(meta, lookup)
            }
            // when feature `no_fixed_lookup` is on, we don't do lookup
            LookupEntry::Fixed { .. }
            | LookupEntry::U8(..)
            | LookupEntry::U10(..)
            | LookupEntry::U16(..) => {
                if cfg!(feature = "no_fixed_lookup") {
                    // when feature `no_fixed_lookup` is on, we don't do lookup
                    vec![(0.expr(), 0.expr())]
                } else {
                    self.fixed_table.get_lookup_vector(meta, lookup)
                }
            }
            LookupEntry::Exp { .. } => self.exp_table.get_lookup_vector(meta, lookup),
            // 此处如果有其它类型的entry应该panic。
            _ => unreachable!(),
        };
        v.into_iter()
            .map(|(left, right)| (condition.clone() * left, right))
            .collect()
    }

    pub(crate) fn get_storage_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        storage_contract_addr_hi: Expression<F>,
        storage_contract_addr_lo: Expression<F>,
        storage_key_hi: Expression<F>,
        storage_key_lo: Expression<F>,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        self.get_state_constraints(
            entry,
            index,
            (state::Tag::Storage as u8).expr(),
            storage_contract_addr_hi * pow_of_two::<F>(128) + storage_contract_addr_lo,
            storage_key_hi,
            storage_key_lo,
            meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                + index.expr(),
            (is_write as u8).expr(),
        )
    }

    pub(crate) fn get_storage_full_constraints_with_tag(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        storage_contract_addr_hi: Expression<F>,
        storage_contract_addr_lo: Expression<F>,
        storage_key_hi: Expression<F>,
        storage_key_lo: Expression<F>,
        state_tag: state::Tag,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        self.get_storage_full_constraints_with_tag_stamp_delta(
            meta,
            entry,
            index,
            prev_exec_state_row,
            storage_contract_addr_hi,
            storage_contract_addr_lo,
            storage_key_hi,
            storage_key_lo,
            state_tag,
            index.expr(),
            is_write,
        )
    }
    pub(crate) fn get_storage_full_constraints_with_tag_stamp_delta(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        storage_contract_addr_hi: Expression<F>,
        storage_contract_addr_lo: Expression<F>,
        storage_key_hi: Expression<F>,
        storage_key_lo: Expression<F>,
        state_tag: state::Tag,
        stamp_delta: Expression<F>,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let (tag, stamp, _, _, call_id_contract_addr, pointer_hi, pointer_lo, lookup_is_write, ..) =
            extract_lookup_expression!(storage, entry);
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        vec![
            (
                format!("state lookup tag[{}] = {:?}", index, state_tag),
                tag - (state_tag as u8).expr(),
            ),
            (
                format!("state stamp for state lookup[{}]", index),
                stamp
                    - meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - stamp_delta,
            ),
            (
                format!("state lookup contract addr[{}]", index),
                call_id_contract_addr
                    - storage_contract_addr_hi * pow_of_two::<F>(128)
                    - storage_contract_addr_lo,
            ),
            (
                format!("pointer_hi (storage key)[{}]", index),
                pointer_hi - storage_key_hi,
            ),
            (
                format!("pointer_lo (storage key)[{}]", index),
                pointer_lo - storage_key_lo,
            ),
            (
                format!("is_write[{}]", index),
                lookup_is_write - (is_write as u8).expr(),
            ),
        ]
    }

    ///generate stack lookup's constraints which are controlled by the selector (enabled when selector != 0.expr() and disabled when selector == 0.expr())
    pub(crate) fn get_stack_constraints_with_selector(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        stack_pointer_delta: Expression<F>, // compare to that of previous state
        is_write: bool,
        selector: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let constraints_raw = self.get_stack_constraints(
            meta,
            entry,
            index,
            prev_exec_state_row,
            stack_pointer_delta,
            is_write,
        );

        let res: Vec<(String, Expression<F>)> = constraints_raw
            .into_iter()
            .map(|constraint| (constraint.0, selector.clone() * constraint.1))
            .collect();

        res
    }

    ///generate storage lookup's constraints which are controlled by the selector (enabled when selector != 0.expr() and disabled when selector == 0.expr())
    pub(crate) fn get_storage_constraints_with_selector(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        storage_contract_addr_hi: Expression<F>,
        storage_contract_addr_lo: Expression<F>,
        storage_key_hi: Expression<F>,
        storage_key_lo: Expression<F>,
        is_write: bool,
        selector: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let constraints_raw = self.get_storage_constraints(
            meta,
            entry,
            index,
            prev_exec_state_row,
            storage_contract_addr_hi,
            storage_contract_addr_lo,
            storage_key_hi,
            storage_key_lo,
            is_write,
        );

        let res: Vec<(String, Expression<F>)> = constraints_raw
            .into_iter()
            .map(|constraint| (constraint.0, selector.clone() * constraint.1))
            .collect();

        res
    }

    pub(crate) fn get_returndata_call_id_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        is_write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = self.get_call_context_constraints(
            meta,
            entry.clone(),
            index,
            prev_exec_state_row,
            is_write,
            (CallContextTag::ReturnDataCallId as u8).expr(),
            0.expr(),
        );
        let (_, _, value_hi, _, _, _, _, _) = extract_lookup_expression!(state, entry);

        constraints.extend([(format!("value_hi[{}]", index), value_hi)]);

        constraints
    }

    pub(crate) fn get_call_context_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        is_write: bool,
        call_context_tag: Expression<F>,
        call_id: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        self.get_state_constraints(
            entry,
            index,
            (state::Tag::CallContext as u8).expr(),
            call_id,
            0.expr(),
            call_context_tag,
            meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                + index.expr(),
            (is_write as u8).expr(),
        )
    }

    pub(crate) fn get_bitwise_constraints(
        &self,
        _meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        tag: Expression<F>,
        acc_0: Expression<F>,
        acc_1: Expression<F>,
        acc_2: Option<Expression<F>>,
        sum_2: Option<Expression<F>>,
    ) -> Vec<(String, Expression<F>)> {
        let (bitwise_tag, bitwise_acc, bitwise_sum_2) = extract_lookup_expression!(bitwise, entry);
        let mut constraints: Vec<(String, Expression<F>)> = vec![];
        constraints.extend([
            ("tag of bitwise lookup".into(), bitwise_tag - tag),
            (
                "acc_0 of bitwise lookup".into(),
                bitwise_acc[0].clone() - acc_0,
            ),
            (
                "acc_1 of bitwise lookup".into(),
                bitwise_acc[1].clone() - acc_1,
            ),
        ]);

        if let Some(acc_2) = acc_2 {
            constraints.push((
                "acc_2 of bitwise lookup".into(),
                bitwise_acc[2].clone() - acc_2,
            ))
        }
        if let Some(sum_2) = sum_2 {
            constraints.push(("sum_2 of bitwise lookup".into(), bitwise_sum_2 - sum_2));
        }
        constraints
    }

    pub(crate) fn get_public_constraints(
        &self,
        _meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        tag: Expression<F>,
        block_tx_idx: Option<Expression<F>>,
        values: [Option<Expression<F>>; PUBLIC_NUM_VALUES],
    ) -> Vec<(String, Expression<F>)> {
        let (public_lookup_tag, public_lookup_block_tx_idx, public_lookup_values) =
            extract_lookup_expression!(public, entry);

        let mut constraints = vec![];
        constraints.push(("public lookup tag".into(), public_lookup_tag - tag));
        if let Some(block_tx_idx) = block_tx_idx {
            constraints.push((
                "public lookup block_tx_idx".into(),
                public_lookup_block_tx_idx - block_tx_idx,
            ));
        }
        for i in 0..PUBLIC_NUM_VALUES {
            if let Some(value) = values[i].clone() {
                constraints.push((
                    format!("public lookup value[{}]", i),
                    public_lookup_values[i].clone() - value,
                ));
            }
        }
        constraints
    }

    pub(crate) fn get_bytecode_full_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (addr, pc, opcode, not_code, value_hi, value_lo, cnt, is_push) = (
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 1], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 2], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 3], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 4], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 5], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 6], Rotation::prev()),
            meta.query_advice(self.vers[BYTECODE_COLUMN_START_IDX + 7], Rotation::prev()),
        );
        LookupEntry::BytecodeFull {
            addr,
            pc,
            opcode,
            not_code,
            value_hi,
            value_lo,
            cnt,
            is_push,
        }
    }

    pub(crate) fn get_fixed_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
        at: Rotation,
    ) -> LookupEntry<F> {
        assert!(index < 2);
        let start_idx = FIXED_COLUMN_START_IDX + index * FIXED_COLUMN_WIDTH;
        let (tag, value_0, value_1, value_2) = (
            meta.query_advice(self.vers[start_idx], at),
            meta.query_advice(self.vers[start_idx + 1], at),
            meta.query_advice(self.vers[start_idx + 2], at),
            meta.query_advice(self.vers[start_idx + 3], at),
        );
        LookupEntry::Fixed {
            tag,
            values: [value_0, value_1, value_2],
        }
    }
    pub(crate) fn get_stamp_cnt_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let tag = meta.query_advice(self.vers[STAMP_CNT_COLUMN_START_IDX], Rotation::prev());
        let cnt = meta.query_advice(self.vers[STAMP_CNT_COLUMN_START_IDX + 1], Rotation::prev());
        LookupEntry::StampCnt { tag, cnt }
    }

    pub(crate) fn get_arithmetic_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        self.get_arithmetic_lookup_with_rotation(meta, index, Rotation(-2))
    }

    pub(crate) fn get_arithmetic_lookup_with_rotation(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
        at: Rotation,
    ) -> LookupEntry<F> {
        assert!(index < 3);
        let (hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3, tag) = (
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 0], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 1], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 2], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 3], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 4], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 5], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 6], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 7], at),
            meta.query_advice(self.vers[index * ARITHMETIC_COLUMN_WIDTH + 8], at),
        );
        LookupEntry::Arithmetic {
            tag,
            values: [hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3],
        }
    }

    pub(crate) fn get_arithmetic_tiny_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        let offset = ARITHMETIC_TINY_START_IDX + index * ARITHMETIC_TINY_COLUMN_WIDTH;

        let (val_0, val_1, val_2, val_3, tag) = (
            meta.query_advice(self.vers[offset + 0], Rotation(-2)),
            meta.query_advice(self.vers[offset + 1], Rotation(-2)),
            meta.query_advice(self.vers[offset + 2], Rotation(-2)),
            meta.query_advice(self.vers[offset + 3], Rotation(-2)),
            meta.query_advice(self.vers[offset + 4], Rotation(-2)),
        );
        LookupEntry::ArithmeticTiny {
            tag,
            values: [val_0, val_1, val_2, val_3],
        }
    }

    pub(crate) fn get_arithmetic_tiny_lookup_with_rotation(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
        at: Rotation,
    ) -> LookupEntry<F> {
        let offset = ARITHMETIC_TINY_START_IDX + index * ARITHMETIC_TINY_COLUMN_WIDTH;

        let (val_0, val_1, val_2, val_3, tag) = (
            meta.query_advice(self.vers[offset + 0], at),
            meta.query_advice(self.vers[offset + 1], at),
            meta.query_advice(self.vers[offset + 2], at),
            meta.query_advice(self.vers[offset + 3], at),
            meta.query_advice(self.vers[offset + 4], at),
        );
        LookupEntry::ArithmeticTiny {
            tag,
            values: [val_0, val_1, val_2, val_3],
        }
    }

    pub(crate) fn get_copy_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize,
    ) -> LookupEntry<F> {
        let column_offset = index * COPY_LOOKUP_COLUMN_CNT;
        let (
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            acc,
        ) = (
            meta.query_advice(self.vers[column_offset], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 1], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 2], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 3], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 4], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 5], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 6], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 7], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 8], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 9], Rotation(-2)),
            meta.query_advice(self.vers[column_offset + 10], Rotation(-2)),
        );
        LookupEntry::Copy {
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            acc,
        }
    }

    pub(crate) fn get_auxiliary(&self) -> Auxiliary {
        Auxiliary {
            state_stamp: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 0],
            stack_pointer: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 1],
            log_stamp: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 2],
            gas_left: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 3],
            refund: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 4],
            memory_chunk: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 5],
            read_only: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 6],
        }
    }

    pub(crate) fn get_begin_tx_constrains(
        &self,
        meta: &mut VirtualCells<F>,
        prev_exec_state_row: usize,
        call_ids: &[Expression<F>],
        tags: &[CallContextTag],
    ) -> Vec<(String, Expression<F>)> {
        assert!(tags.len() < 5);
        assert_eq!(call_ids.len(), tags.len());

        let mut constraints = vec![];
        for (i, (call_id, tag)) in call_ids.iter().zip(tags.iter()).enumerate() {
            let entry = self.get_state_lookup(meta, i);
            constraints.append(&mut self.get_call_context_constraints(
                meta,
                entry.clone(),
                i,
                prev_exec_state_row,
                true,
                (*tag as u8).expr(),
                call_id.clone(),
            ));
        }
        constraints
    }

    #[allow(unused)]
    pub(crate) fn get_auxiliary_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        prev_exec_state_row: usize,
        delta: AuxiliaryOutcome<F>,
    ) -> Vec<(String, Expression<F>)> {
        let Auxiliary {
            state_stamp,
            stack_pointer,
            log_stamp,
            gas_left,
            refund,
            memory_chunk,
            read_only,
        } = self.get_auxiliary();
        let mut constraints: Vec<(String, Expression<F>)> = vec![];
        // state stamp constraint
        constraints.extend(
            delta
                .state_stamp
                .into_constraint(
                    meta.query_advice(state_stamp, Rotation::cur()),
                    meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("state stamp cur - prev - delta".into(), expr)),
        );
        // stack pointer constraint
        constraints.extend(
            delta
                .stack_pointer
                .into_constraint(
                    meta.query_advice(stack_pointer, Rotation::cur()),
                    meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("stack pointer cur - prev - delta".into(), expr)),
        );
        // log stamp constraint
        constraints.extend(
            delta
                .log_stamp
                .into_constraint(
                    meta.query_advice(log_stamp, Rotation::cur()),
                    meta.query_advice(log_stamp, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("log stamp cur - prev - delta".into(), expr)),
        );
        // read only constraint
        constraints.extend(
            delta
                .read_only
                .into_constraint(
                    meta.query_advice(read_only, Rotation::cur()),
                    meta.query_advice(read_only, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("read only cur - prev - delta".into(), expr)),
        );
        // memory chunk constraint
        constraints.extend(
            delta
                .memory_chunk
                .into_constraint(
                    meta.query_advice(memory_chunk, Rotation::cur()),
                    meta.query_advice(memory_chunk, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("memory chunk cur - prev - delta".into(), expr)),
        );
        // gas_left constraint
        constraints.extend(
            delta
                .gas_left
                .into_constraint(
                    meta.query_advice(gas_left, Rotation::cur()),
                    meta.query_advice(gas_left, Rotation(-1 * prev_exec_state_row as i32)),
                )
                .map(|expr| ("gas left prev - cur - delta".into(), expr)),
        );

        // todo 需要预处理
        // constraints.extend(
        //     delta
        //         .refund
        //         .into_constraint(
        //             meta.query_advice(gas_left, Rotation::cur()),
        //             meta.query_advice(gas_left, Rotation(-1 * prev_exec_state_row as i32)),
        //         )
        //         .map(|expr| ("refund cur - prev - delta".into(), expr)),
        // );
        //todo other auxiliary
        constraints
    }

    /// get_next_single_purpose_constraints get constraints of pc, block_idx, tx_idx, call_id, code_addr
    /// between rotation::cur() and rotation::next()
    pub(crate) fn get_next_single_purpose_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        delta: CoreSinglePurposeOutcome<F>,
    ) -> Vec<(String, Expression<F>)> {
        self.get_core_single_purpose_constraints(meta, 1, delta, "next")
    }

    /// get_cur_single_purpose_constraints get constraints of pc, block_idx, tx_idx, call_id, code_addr
    /// between rotation::cur() and rotation(-1 * prev_exec_state_row)
    pub(crate) fn get_cur_single_purpose_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        prev_exec_state_row: usize,
        delta: CoreSinglePurposeOutcome<F>,
    ) -> Vec<(String, Expression<F>)> {
        self.get_core_single_purpose_constraints(
            meta,
            -1 * prev_exec_state_row as i32,
            delta,
            "prev",
        )
    }

    /// get_core_single_purpose_constraints compute pc, block_idx, tx_idx, call_id, code_addr constraints
    fn get_core_single_purpose_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        roation_row: i32,
        delta: CoreSinglePurposeOutcome<F>,
        comment_postfix: &str,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints: Vec<(String, Expression<F>)> = vec![];

        let (rotation_1, rotation_2) = if roation_row > 0 {
            (Rotation(roation_row), Rotation::cur())
        } else {
            (Rotation::cur(), Rotation(roation_row))
        };

        // pc constraint
        constraints.extend(
            delta
                .pc
                .into_constraint(
                    meta.query_advice(self.pc, rotation_1.clone()),
                    meta.query_advice(self.pc, rotation_2.clone()),
                )
                .map(|expr| (format!("pc {}", comment_postfix), expr)),
        );
        //  block_idx next constraint
        constraints.extend(
            delta
                .block_idx
                .into_constraint(
                    meta.query_advice(self.block_idx, rotation_1.clone()),
                    meta.query_advice(self.block_idx, rotation_2.clone()),
                )
                .map(|expr| (format!("block_idx {}", comment_postfix), expr)),
        );
        // tx_idx next constraint
        constraints.extend(
            delta
                .tx_idx
                .into_constraint(
                    meta.query_advice(self.tx_idx, rotation_1.clone()),
                    meta.query_advice(self.tx_idx, rotation_2.clone()),
                )
                .map(|expr| (format!("tx_idx {}", comment_postfix), expr)),
        );
        // tx_is_create next constraint
        constraints.extend(
            delta
                .tx_is_create
                .into_constraint(
                    meta.query_advice(self.tx_is_create, rotation_1.clone()),
                    meta.query_advice(self.tx_is_create, rotation_2.clone()),
                )
                .map(|expr| (format!("tx_is_create {}", comment_postfix), expr)),
        );
        // call_id next constraint
        constraints.extend(
            delta
                .call_id
                .into_constraint(
                    meta.query_advice(self.call_id, rotation_1.clone()),
                    meta.query_advice(self.call_id, rotation_2.clone()),
                )
                .map(|expr| (format!("call_id {}", comment_postfix), expr)),
        );
        constraints.extend(
            delta
                .code_addr
                .into_constraint(
                    meta.query_advice(self.code_addr, rotation_1.clone()),
                    meta.query_advice(self.code_addr, rotation_2.clone()),
                )
                .map(|expr| (format!("code_addr {}", comment_postfix), expr)),
        );
        constraints
    }

    pub(crate) fn get_log_left_selector(&self, meta: &mut VirtualCells<F>) -> SimpleSelector<F, 5> {
        let selector = SimpleSelector::new(&[
            meta.query_advice(self.vers[LOG_SELECTOR_COLUMN_START_IDX], Rotation::prev()), // LOG_LEFT_4
            meta.query_advice(
                self.vers[LOG_SELECTOR_COLUMN_START_IDX + 1],
                Rotation::prev(),
            ), // LOG_LEFT_3
            meta.query_advice(
                self.vers[LOG_SELECTOR_COLUMN_START_IDX + 2],
                Rotation::prev(),
            ), // LOG_LEFT_2
            meta.query_advice(
                self.vers[LOG_SELECTOR_COLUMN_START_IDX + 3],
                Rotation::prev(),
            ), // LOG_LEFT_1
            meta.query_advice(
                self.vers[LOG_SELECTOR_COLUMN_START_IDX + 4],
                Rotation::prev(),
            ), // LOG_LEFT_0
        ]);
        selector
    }
    // get_exec_state_constraints usage:
    // if state_transition.prev_states.len() > 0,
    //    prev_constraints: sum(prev_cond_expr) -1.expr()
    // if state_transition.next_stats.len() > 0 && state_transition.next_states_cond.len() > 0 , next_constraints:
    //    sum(cond*(next_cnt_is_zero*next_selector-1))),
    // if has cond,cond must be 1 or 0
    // if state_transition.next_stats.len() > 0 && state_transition.next_states_cond.len()== 0 , next_constraints:
    //    sum(next_cnt_is_zero*next_selector) - 1.expr
    pub(crate) fn get_exec_state_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        state_transition: ExecStateTransition<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        // prev constraints
        let mut prev_cond_expr = 0.expr();
        let prev_state_len = state_transition.prev_states.len();
        for prev_state in state_transition.prev_states {
            prev_cond_expr = prev_cond_expr
                + self.execution_state_selector.selector(
                    meta,
                    prev_state as usize,
                    Rotation(-1 * state_transition.current_gadget_num_rows as i32),
                );
        }
        if prev_state_len > 0 {
            constraints.push(("prev state constraints".into(), prev_cond_expr - 1.expr()));
        }
        // next constraints
        let mut next_cond_expr = 0.expr();
        let next_state_len = state_transition.next_states.len();
        let (next_states_cond, next_states_cond_len) = match state_transition.next_states_cond {
            Some(cond) => {
                let cond_len = cond.len();
                // cond_len 必须等于next_states的长度
                assert!(next_state_len == cond_len);
                (cond, cond_len)
            }
            None => (vec![], 0),
        };

        for (state_index, (next_state, num_row, next_state_num_row_cond)) in
            state_transition.next_states.iter().enumerate()
        {
            let next_cnt_is_zero = self.cnt_is_zero.expr_at(meta, Rotation(*num_row as i32));
            let mut cnt_is_zero_plus_selector_expr = next_cnt_is_zero
                * self.execution_state_selector.selector(
                    meta,
                    *next_state as usize,
                    Rotation(*num_row as i32),
                );
            cnt_is_zero_plus_selector_expr = match next_state_num_row_cond {
                Some(state_num_row) => {
                    constraints.push((
                        "next state selector constraints".into(),
                        cnt_is_zero_plus_selector_expr.clone() - state_num_row.clone(),
                    ));
                    state_num_row.clone()
                }
                None => cnt_is_zero_plus_selector_expr,
            };

            let current_state_cond_expr = if next_states_cond_len > 0 {
                next_states_cond.get(state_index).unwrap().clone()
                    * (cnt_is_zero_plus_selector_expr - 1.expr())
            } else {
                cnt_is_zero_plus_selector_expr
            };
            next_cond_expr = next_cond_expr + current_state_cond_expr;
        }
        let next_state_constraints = if next_states_cond_len > 0 {
            next_cond_expr
        } else {
            next_cond_expr - 1.expr()
        };
        if next_state_len > 0 {
            constraints.push(("next state constraints".into(), next_state_constraints));
        }
        constraints
    }

    // get_shl_shr_sar1_sub_arith_constraints usage:
    // sub_arithmetic_operands[0](sub_arithmetic operand_0 hi) is 0
    // sub_arithmetic_operands[1](sub_arithmetic operand_0 lo) is 255
    // sub_arithmetic_operands[2](sub_arithmetic operand_1 hi) is shift hi (stack top 0 hi)
    // sub_arithmetic_operands[3](sub_arithmetic operand_1 lo) is shift lo (stack top 0 lo)
    // sub_arithmetic_operands[6] is carry hi
    // sub_arithmetic_operands[7] is carry lo
    // if carry = 1 , mul_div_num = 0;
    // if carry = 1 , mul_div_arithmetic_operands[5] = 0 (product_or_quotient hi = 0)
    //                mul_div_arithmetic_operands[6] = 0 (product_or_quotient lo = 0)
    pub(crate) fn get_shl_shr_sar1_sub_arith_constraints(
        &self,
        stack_operand: &[Expression<F>; 2],
        mul_div_arithmetic_operands: &[Expression<F>; 8],
        sub_arithmetic_operands: &[Expression<F>; 8],
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        constraints.extend([
            (
                "sub_arithmetic operand_0 hi = 0".into(),
                sub_arithmetic_operands[0].clone(),
            ),
            (
                "sub_arithmetic operand_0 lo = 255".into(),
                sub_arithmetic_operands[1].clone() - 255.expr(),
            ),
            (
                "sub_arithmetic operand_1 hi = shift hi(stack top0 hi)".into(),
                sub_arithmetic_operands[2].clone() - stack_operand[0].clone(),
            ),
            (
                "sub_arithmetic operand_1 lo= shift lo(stack top0 lo)".into(),
                sub_arithmetic_operands[3].clone() - stack_operand[1].clone(),
            ),
            // if the divisor is 0, the quotient and remainder in Arithmetic-DivMod must be 0
            (
                "sub_arithmetic carry=1 => mul_div_num hi = 0".into(),
                sub_arithmetic_operands[6].clone() * mul_div_arithmetic_operands[2].clone(),
            ),
            (
                "sub_arithmetic carry=1 => mul_div_num lo = 0".into(),
                sub_arithmetic_operands[6].clone() * mul_div_arithmetic_operands[3].clone(),
            ),
        ]);
        constraints
    }

    // get_mul_div_arithmetic_constraints usage:
    // mul_div_arithmetic_operands[0] = stack top 1 hi  (original value)
    // mul_div_arithmetic_operands[1] = stack top 1 lo (original value)
    // mul_div_arithmetic_operands[2] = exp_power
    // mul_div_arithmetic_operands[3] = exp_power
    // mul_div_arithmetic_operands[4](product_hi) = stack push hi (shift results left or right hi)
    // mul_div_arithmetic_operands[5](product_lo) = stack push lo (shift results left or right lo)
    // mul_div_arithmetic_operands[6] is carry
    // mul_div_arithmetic_operands[7] is carry
    // product_or_quotient:
    //       mul_div_arithmetic_operands[5] = stack push hi
    //       mul_div_arithmetic_operands[6] = stack push lo
    pub(crate) fn get_shl_shr_sar1_mul_div_arith_constraints(
        &self,
        operand: &[Expression<F>; 2],
        result: &[Expression<F>; 2],
        mul_div_arithmetic_operands: &[Expression<F>; 8],
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        constraints.extend([
            (
                "mul_div_arithmetic operand_0 hi = stack top_1 hi".into(),
                mul_div_arithmetic_operands[0].clone() - operand[0].clone(),
            ),
            (
                "mul_div_arithmetic operand_0 lo= stack top_1 lo".into(),
                mul_div_arithmetic_operands[1].clone() - operand[1].clone(),
            ),
            (
                "mul_div_arithmetic product_or_quotient hi = stack push hi".into(),
                mul_div_arithmetic_operands[4].clone() - result[0].clone(),
            ),
            (
                "mul_div_arithmetic product_or_quotient lo = stack push lo".into(),
                mul_div_arithmetic_operands[5].clone() - result[1].clone(),
            ),
        ]);
        constraints
    }

    // get_shl_shr_sar1_exp_constraints usage:
    // exp_base = 2
    // exp_index_hi = stack top 0 hi (shift value)
    // exp_index_lo = stack top 0 lo (shift value)
    // exp_power_hi = mul_num hi
    // exp_power_lo = mul_num lo
    pub(crate) fn get_shl_shr_sar1_exp_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        stack_operand: &[Expression<F>; 2],
        mul_div_arithmetic_operands: &[Expression<F>; 8],
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        let entry = self.get_exp_lookup(meta);
        let (exp_base, exp_index, exp_power) = extract_lookup_expression!(exp, entry);
        constraints.extend([
            ("exp_base hi".into(), exp_base[0].clone()),
            ("exp_base lo".into(), exp_base[1].clone() - 2.expr()),
            (
                "exp_index hi = stack top_0 hi".into(),
                exp_index[0].clone() - stack_operand[0].clone(),
            ),
            (
                "exp_index lo = stack top_0 lo".into(),
                exp_index[1].clone() - stack_operand[1].clone(),
            ),
            (
                "exp_power = mul_div_num hi".into(),
                exp_power[0].clone() - mul_div_arithmetic_operands[2].clone(),
            ),
            (
                "exp_power = mul_div_num lo".into(),
                exp_power[1].clone() - mul_div_arithmetic_operands[3].clone(),
            ),
        ]);
        constraints
    }

    pub(crate) fn get_signextend_bitwise_lookups(
        &self,
        meta: &mut VirtualCells<F>,
        sign_bit_is_zero_inv: Expression<F>,
    ) -> (Vec<LookupEntry<F>>, SimpleIsZero<F>) {
        // bitwise lookup constraints
        // operand_1 & a
        // operand_1 operator d  constraints
        let mut bitwise_lookups = vec![];
        let mut sign_bit_is_zero_v = 0.expr();
        for i in 0..4 {
            let entry = self.get_bitwise_lookup(meta, i);
            let (_, _, sum) = extract_lookup_expression!(bitwise, entry.clone());
            if i < 2 {
                sign_bit_is_zero_v = sign_bit_is_zero_v + sum.clone();
            }
            bitwise_lookups.push(entry);
        }

        let sign_bit_is_zero = SimpleIsZero::new(
            &sign_bit_is_zero_v,
            &sign_bit_is_zero_inv,
            String::from("length_lo"),
        );

        (bitwise_lookups, sign_bit_is_zero)
    }

    pub(crate) fn get_signextend_bitwise_constraints(
        &self,
        bitwise_lookups: Vec<LookupEntry<F>>,
        signextend_a: [Expression<F>; 2],
        signextend_operand1: [Expression<F>; 2],
        signextend_d: [Expression<F>; 2],
        signextend_expect_result: [Expression<F>; 2],
        sign_bit_is_zero: Expression<F>,
        shift_gt_range: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        for (i, entry) in bitwise_lookups.iter().enumerate() {
            let (tag, acc, _) = extract_lookup_expression!(bitwise, entry);
            // left operand constraints
            let left_operand_constraint = (
                format!(
                    "bitwise[{}] left operand = signextend_operand1[{}]",
                    i,
                    i % 2
                ),
                acc[0].clone() - signextend_operand1[i % 2].clone(),
            );
            // right operand constraints
            let right_operand_constraints = if i < 2 {
                (
                    format!("bitwise[{}] right operand = signextend_a[{}]", i, i % 2),
                    acc[1].clone() - signextend_a[i % 2].clone(),
                )
            } else {
                (
                    format!("bitwise[{}] right operand = signextend_d[{}]", i, i % 2),
                    acc[1].clone() - signextend_d[i % 2].clone(),
                )
            };
            // operator constraints
            let operator_constraints = if i < 2 {
                (
                    format!("bitwise[{}] operator = opAnd ", i),
                    tag.clone() - (bitwise::Tag::And as u8).expr(),
                )
            } else {
                (
                    format!("bitwise[{}] operator", i),
                    sign_bit_is_zero.expr() * (tag.clone() - (bitwise::Tag::And as u8).expr())
                        + (1.expr() - sign_bit_is_zero.expr()).clone()
                            * (tag.clone() - (bitwise::Tag::Or as u8).expr()),
                )
            };
            // constraints
            constraints.extend([
                left_operand_constraint,
                right_operand_constraints,
                operator_constraints,
            ]);
            // i > 2: final_result constraints
            if i >= 2 {
                constraints.extend([(
                    format!("signextend_result[{}] = acc[2]", i % 2),
                    signextend_expect_result[i % 2].clone() - acc[2].clone(),
                )]);

                // if shift > 255, final_result = operands[1]
                constraints.extend([(
                    format!(
                        "shift > 255 =>  signextend_result[{}] = signextend_operand1[{}]",
                        i % 2,
                        i % 2
                    ),
                    shift_gt_range.clone()
                        * (signextend_expect_result[i % 2].clone()
                            - signextend_operand1[i % 2].clone()),
                )])
            }
        }
        constraints
    }

    pub(crate) fn get_signextend_operands(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> (
        Expression<F>,
        Expression<F>,
        Expression<F>,
        Expression<F>,
        Expression<F>,
    ) {
        const SKIP_WIDTH: usize =
            constant::NUM_STATE_HI_COL + constant::NUM_STATE_LO_COL + constant::NUM_AUXILIARY;
        (
            // [a_hi,a_lo]
            meta.query_advice(self.vers[SKIP_WIDTH], Rotation::cur()),
            meta.query_advice(self.vers[SKIP_WIDTH + 1], Rotation::cur()),
            // [d_hi,d_lo]
            meta.query_advice(self.vers[SKIP_WIDTH + 2], Rotation::cur()),
            meta.query_advice(self.vers[SKIP_WIDTH + 3], Rotation::cur()),
            // not_is_zero
            meta.query_advice(self.vers[SKIP_WIDTH + 4], Rotation::cur()),
        )
    }

    pub(crate) fn get_signextend_sub_arith_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        stack_top0: Vec<Expression<F>>,
        bit_or_byte_range: Expression<F>,
    ) -> (Vec<(String, Expression<F>)>, Expression<F>) {
        let mut constraints = vec![];
        let (arithmetic_tag, arithmetic_operands) =
            extract_lookup_expression!(arithmetic, self.get_arithmetic_lookup(meta, 0));
        // arithmetic_operands[0] is 0
        // arithmetic_operands[1] is 31 or 255
        // arithmetic_operands[2] is operand0_hi
        // arithmetic_operands[3] is operand0_lo
        // arithmetic_operands[6] is carry
        // arithmetic_operands[7] is carry
        constraints.extend([
            (
                "arithmetic_operands[0] = 0".into(),
                arithmetic_operands[0].clone(),
            ),
            (
                "arithmetic_operands[1] = 31(byte) or 255(bit)".into(),
                arithmetic_operands[1].clone() - bit_or_byte_range,
            ),
            (
                "arithmetic_operands[2] = stack_top_0_hi".into(),
                arithmetic_operands[2].clone() - stack_top0[0].clone(),
            ),
            (
                "arithmetic_operands[3] = stack_top_0_lo".into(),
                arithmetic_operands[3].clone() - stack_top0[1].clone(),
            ),
        ]);

        // arithmetic tag constraints
        constraints.push((
            "arithmetic tag is sub".into(),
            arithmetic_tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
        ));

        (constraints, arithmetic_operands[6].clone())
    }
}

// ExecStateTransition record state transition
pub(crate) struct ExecStateTransition<F> {
    pub(crate) prev_states: Vec<ExecutionState>,
    // current_gadget_num_rows current gadget num row in core
    pub(crate) current_gadget_num_rows: usize,
    // next_states ,vector of (next gadget state ,next gadget num row in core,
    // next gadget selector multiply next gadget cnt is zero),the option is used for
    // some gadget, which has next_states_cond ,to lower the degree
    pub(crate) next_states: Vec<(ExecutionState, usize, Option<Expression<F>>)>,
    // next state cond vector if exists, length must equal next_states's length
    pub(crate) next_states_cond: Option<Vec<Expression<F>>>,
}
impl<F: Field> ExecStateTransition<F> {
    pub fn new(
        prev_states: Vec<ExecutionState>,
        current_gadget_num_rows: usize,
        next_states: Vec<(ExecutionState, usize, Option<Expression<F>>)>,
        next_states_cond: Option<Vec<Expression<F>>>,
    ) -> Self {
        Self {
            prev_states,
            current_gadget_num_rows,
            next_states,
            next_states_cond,
        }
    }
}

/// Execution Gadget for the configure and witness generation of an execution state
pub(crate) trait ExecutionGadget<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>
{
    fn name(&self) -> &'static str;
    fn execution_state(&self) -> ExecutionState;
    /// Number of rows this execution state will use in core circuit
    fn num_row(&self) -> usize;
    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows(&self) -> (usize, usize);

    /// Get gate constraints for this execution state (without condition).
    /// Rotation::cur() in the constraints means the row that column config.cnt is 0
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)>;

    /// Get lookups for this execution state, prepared for merging lookups among all states
    /// Rotation::cur() in the lookups means the row that column config.cnt is 0
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)>;

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness;
}

#[derive(Clone)]
pub(crate) struct ExecutionGadgets<const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> {
}

impl<const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadgets<NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub(crate) fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        config: ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    ) -> Self {
        let gadgets: Vec<Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>> =
            get_every_execution_gadgets!();

        let mut lookups_to_merge = vec![];
        meta.create_gate("q_first_exec_state constrains", |meta| {
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let q_first_exec_state = meta.query_selector(config.q_first_exec_state);
            let execution_state_selector = config.execution_state_selector.selector(
                meta,
                ExecutionState::BEGIN_CHUNK as usize,
                Rotation::cur(),
            );
            vec![
                (
                    "q_first_exec_state=1 ==> cnt=0",
                    q_first_exec_state.clone() * cnt,
                ),
                (
                    "q_first_exec_state=1 => gadget=begin_chunk",
                    q_first_exec_state * (1.expr() - execution_state_selector),
                ),
            ]
        });

        for gadget in &gadgets {
            // the constraints that all execution state requires, e.g., cnt=num_row-1 at the first row
            meta.create_gate(format!("EXECUTION_STATE_{}", gadget.name()), |meta| {
                let q_enable = meta.query_selector(config.q_enable);
                let num_row = gadget.num_row();
                let cnt_prev_state = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32));
                // cnt in first row of this state
                let cnt_first = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32 + 1));
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let execution_state_selector = config.execution_state_selector.selector(
                    meta,
                    gadget.execution_state() as usize,
                    Rotation::cur(),
                );
                let condition = q_enable * cnt_is_zero * execution_state_selector;
                vec![
                    (
                        "prev state last cnt = 0",
                        condition.clone() * cnt_prev_state,
                    ),
                    (
                        "this state first cnt is const",
                        condition.clone() * (cnt_first - (num_row - 1).expr()),
                    ),
                ]
            });
            // the constraints for the specific execution state, extracted from the gadget
            meta.create_gate(format!("EXECUTION_GADGET_{}", gadget.name()), |meta| {
                // constraints without condition
                let constraints = gadget.get_constraints(&config, meta);
                if constraints.is_empty() {
                    return vec![("placeholder due to no constraint".into(), 0.expr())];
                }
                let q_enable = meta.query_selector(config.q_enable);
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let execution_state_selector = config.execution_state_selector.selector(
                    meta,
                    gadget.execution_state() as usize,
                    Rotation::cur(),
                );
                let condition = q_enable * cnt_is_zero * execution_state_selector;
                constraints
                    .into_iter()
                    .map(|(s, e)| (s, condition.clone() * e))
                    .collect::<Vec<(String, Expression<F>)>>()
            });
            // extract lookups
            let execution_state = gadget.execution_state();
            let mut lookups = gadget
                .get_lookups(&config, meta)
                .into_iter()
                .map(|(string, lookup)| (string, lookup, execution_state))
                .collect();
            lookups_to_merge.append(&mut lookups);
        }

        #[cfg(feature = "no_lookup_merge")]
        for (string, lookup, execution_state) in lookups_to_merge {
            match lookup {
                LookupEntry::BytecodeFull { .. }
                | LookupEntry::State { .. }
                | LookupEntry::Storage { .. }
                | LookupEntry::Bytecode { .. }
                | LookupEntry::Public { .. }
                | LookupEntry::Arithmetic { .. }
                | LookupEntry::ArithmeticTiny { .. }
                | LookupEntry::Fixed { .. }
                | LookupEntry::U8(..)
                | LookupEntry::U10(..)
                | LookupEntry::U16(..)
                | LookupEntry::Bitwise { .. }
                | LookupEntry::MostSignificantByteLen { .. }
                | LookupEntry::Copy { .. }
                | LookupEntry::ArithmeticShort { .. }
                | LookupEntry::Exp { .. } => {
                    meta.lookup_any(string, |meta| {
                        let q_enable = meta.query_selector(config.q_enable);
                        let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                        let execution_state_selector = config.execution_state_selector.selector(
                            meta,
                            execution_state as usize,
                            Rotation::cur(),
                        );
                        let condition = q_enable.clone() * cnt_is_zero * execution_state_selector;
                        config.get_lookup_constraints(meta, lookup, condition)
                    });
                }
                _ => (),
            };
        }

        // 对lookup entry依据identifier进行归类. 相同类别的look entry 组成一个vec![]
        // lookup_category, key 为每类lookup entry的标识，每个lookup entry由不同数量
        // 的表达式组成，每个表达式有唯一的标识，key是一系列表达式的集合。
        // value为同类的lookup entry.
        // examples：
        // key = advice[32][-1]-advice[33][-1]-advice[34][-1]-advice[35][-1]
        //       -advice[36][-1]-advice[37][-1]-advice[38][-1]-advice[39][-1]
        // advice[32][-1]: 表示组成lookup entry的第一个表达式处于advice [第几列][第几行]，
        // “-”：组成lookup entry的不同表达式间的分隔符。
        // values = [("stack pop b", State { tag: Advice { query_index: 55, column_index: 32, rotation: Rotation(-1)
        //     }, stamp: Advice { query_index: 56, column_index: 33, rotation: Rotation(-1)
        //     }, value_hi: Advice { query_index: 57, column_index: 34, rotation: Rotation(-1)
        //     ....
        //     }, is_write: Advice { query_index: 62, column_index: 39, rotation: Rotation(-1)
        //     }
        // }, ADD), ("stack push b", State { tag: Advice { query_index: 55, column_index: 32, rotation: Rotation(-1)
        //     }, stamp: Advice { query_index: 56, column_index: 33, rotation: Rotation(-1)
        //     }, value_hi: Advice { query_index: 57, column_index: 34, rotation: Rotation(-1)
        //     ...
        //     }, is_write: Advice { query_index: 62, column_index: 39, rotation: Rotation(-1)
        //     }
        // }, ISZERO), ...]
        // 如上，不同gadget(ADD, ISZERO) 使用相同变量的列/行，可以将它们归为一类，lookup 时只需要进行一次即可。
        // tag表达式，不同gadget使用的是Advice第32列（column_index）上一行数据（rotation 相对当前位置），
        // query_index 标识符在证明和验证过程中的查询顺序，确保标识符在评估和验证约束时按正确的顺序进行计算。
        #[cfg(not(feature = "no_lookup_merge"))]
        let mut lookup_category: BTreeMap<
            String,
            Vec<(String, LookupEntry<F>, ExecutionState)>,
        > = BTreeMap::new();
        #[cfg(not(feature = "no_lookup_merge"))]
        for (string, lookup, execution_state) in lookups_to_merge {
            match lookup {
                LookupEntry::BytecodeFull { .. }
                | LookupEntry::State { .. }
                | LookupEntry::Bytecode { .. }
                | LookupEntry::Public { .. }
                | LookupEntry::Arithmetic { .. }
                | LookupEntry::ArithmeticTiny { .. }
                | LookupEntry::Fixed { .. }
                | LookupEntry::U8(..)
                | LookupEntry::U10(..)
                | LookupEntry::U16(..)
                | LookupEntry::Bitwise { .. }
                | LookupEntry::Copy { .. }
                | LookupEntry::ArithmeticShort { .. }
                | LookupEntry::Exp { .. } => {
                    let identifier = lookup.identifier();
                    match lookup_category.get_mut(&identifier) {
                        Some(v) => v.push((string, lookup, execution_state)),
                        None => {
                            lookup_category
                                .insert(identifier, vec![(string, lookup, execution_state)]);
                        }
                    };
                }
                //TODO config还未添加其它table
                _ => (),
            }
        }

        // 对不同归类的内容进行lookup
        #[cfg(not(feature = "no_lookup_merge"))]
        for (_, lookup_vec) in lookup_category {
            // 将同一类中所有lookup entry的annotate合并作为meta.lookup_any的name标识
            let annotates: Vec<&str> = lookup_vec
                .iter()
                .map(|(annote, _, _)| annote.as_str())
                .collect();
            let annotates = annotates.join(ANNOTATE_SEPARATOR);

            meta.lookup_any(annotates, |meta| {
                // 计算同一类中不同lookup entry的condition总和。
                let mut condition: Expression<F> = 0.expr();
                let q_enable = meta.query_selector(config.q_enable);
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                for (_, _, execution_state) in lookup_vec.iter() {
                    let execution_state_selector = config.execution_state_selector.selector(
                        meta,
                        *execution_state as usize,
                        Rotation::cur(),
                    );
                    condition = condition + execution_state_selector;
                }

                condition = q_enable * condition * cnt_is_zero;
                // 因为一类lookup entry集合中的所有元素使用的是相同类型列、相同列数的相同行，
                // 所以只需要lookup 归类集合中的第一个entry即可。
                let (_, lookup, _) = lookup_vec.into_iter().next().unwrap();
                config.get_lookup_constraints(meta, lookup, condition)
            });
        }

        ExecutionGadgets {}
    }

    pub(crate) fn unusable_rows<F: Field>() -> (usize, usize) {
        let gadgets: Vec<Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>> =
            get_every_execution_gadgets!();
        let unusable_begin =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().0)).unwrap();
        let unusable_end =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().1)).unwrap();
        (unusable_begin, unusable_end)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, EnumCountMacro, Eq, Hash, PartialEq, Serialize)]
pub enum ExecutionState {
    // zkevm internal states
    /// State that is padding at the end
    END_PADDING, // it has to be the first state as it is the padding state
    BEGIN_TX_1, // start a tx, part one
    BEGIN_TX_2, // start a tx, part two
    BEGIN_TX_3, // start a tx, part three
    BEGIN_BLOCK,
    BEGIN_CHUNK,
    END_BLOCK,
    END_CHUNK,
    // opcode/operation successful states
    STOP,
    ADD_SUB_MUL_DIV_MOD,
    EXP,
    ADDMOD,
    MULMOD,
    POP,
    PUSH,
    ISZERO,
    AND_OR_XOR,
    NOT,
    JUMP,
    JUMPDEST,
    //JUMP_ERR_OUTOFBOUND,
    JUMPI,
    PUBLIC_CONTEXT,
    BLOCKHASH,
    TX_CONTEXT,
    MEMORY,
    MSTORE8,
    STATUS_INFO,
    STORAGE,
    TSTORAGE,
    CALL_CONTEXT,
    CALLDATALOAD,
    CALLDATACOPY,
    //CALLDATA_FROMPUBLIC,
    LOG_BYTES,
    LOG_TOPIC,
    LOG_TOPIC_NUM_ADDR,
    EQ,
    LT_GT_SLT_SGT,
    DUP,
    SWAP,
    BYTE,
    RETURNDATASIZE,
    RETURN_REVERT,
    SHL_SHR,
    SAR_1,
    SAR_2,
    KECCAK,
    MCOPY,
    CODECOPY,
    EXTCODECOPY,
    SELFBALANCE,
    RETURNDATACOPY,
    SIGNEXTEND,
    CALL_1,
    CALL_2,
    CALL_3,
    CALL_4,
    CALL_5,
    CALL_6,
    CALL_7,
    POST_CALL_1,
    POST_CALL_2,
    END_TX,
    SDIV_SMOD,
    GAS,
    CODESIZE,
    EXTCODEINFO,
    ISZERO_EQ,
    MEMORY_GAS,
    MEMORY_COPIER_GAS,
    PURE_MEMORY_GAS,
    LOG_GAS,
    BALANCE,
    ERROR_INVALID_JUMP,
    ERROR_INVALID_OPCODE,
    ERROR_INVALID_STACK_POINTER, // stack pointer is out of range, StackUnderflow & StackOverflow
    ERROR_OOG_CONSTANT,
    END_CALL_1,
    END_CALL_2,
    ERROR_OOG_ACCOUNT_ACCESS,
    ERROR_OOG_LOG,
    UNSUPPORTED,
}

impl ExecutionState {
    // a mapping from opcode to execution state(s)
    pub fn from_opcode(opcode: OpcodeId) -> Vec<Self> {
        match opcode {
            OpcodeId::STOP => vec![Self::STOP, Self::END_CALL_1, Self::END_CALL_2],
            OpcodeId::ADD | OpcodeId::MUL | OpcodeId::SUB | OpcodeId::DIV | OpcodeId::MOD => {
                vec![Self::ADD_SUB_MUL_DIV_MOD]
            }
            OpcodeId::SDIV | OpcodeId::SMOD => vec![Self::SDIV_SMOD],
            OpcodeId::ADDMOD => vec![Self::ADDMOD],
            OpcodeId::MULMOD => vec![Self::MULMOD],
            OpcodeId::EXP => {
                vec![Self::EXP]
            }
            OpcodeId::SIGNEXTEND => {
                vec![Self::SIGNEXTEND]
            }
            OpcodeId::LT | OpcodeId::GT | OpcodeId::SLT | OpcodeId::SGT => {
                vec![Self::LT_GT_SLT_SGT]
            }
            OpcodeId::EQ | OpcodeId::ISZERO => vec![Self::ISZERO_EQ],
            OpcodeId::AND | OpcodeId::OR | OpcodeId::XOR => vec![Self::AND_OR_XOR],
            OpcodeId::NOT => vec![Self::NOT],
            OpcodeId::BYTE => vec![Self::BYTE],
            OpcodeId::CALLDATALOAD => vec![Self::CALLDATALOAD],
            OpcodeId::CALLDATACOPY => vec![
                Self::CALLDATACOPY,
                Self::MEMORY_GAS,
                Self::MEMORY_COPIER_GAS,
            ],
            OpcodeId::CODESIZE => vec![Self::CODESIZE],
            OpcodeId::CODECOPY => {
                vec![Self::CODECOPY, Self::MEMORY_GAS, Self::MEMORY_COPIER_GAS]
            }
            OpcodeId::SHL | OpcodeId::SHR => vec![Self::SHL_SHR],
            OpcodeId::SAR => {
                vec![Self::SAR_1, Self::SAR_2]
            }
            OpcodeId::POP => {
                vec![Self::POP]
            }
            OpcodeId::MLOAD | OpcodeId::MSTORE => {
                vec![Self::MEMORY, Self::MEMORY_GAS, Self::PURE_MEMORY_GAS]
            }
            OpcodeId::MSTORE8 => vec![Self::MSTORE8, Self::MEMORY_GAS, Self::PURE_MEMORY_GAS],
            OpcodeId::JUMP => vec![Self::JUMP],
            OpcodeId::JUMPI => vec![Self::JUMPI],
            OpcodeId::MSIZE | OpcodeId::PC | OpcodeId::GAS => vec![Self::STATUS_INFO],
            OpcodeId::JUMPDEST => vec![Self::JUMPDEST],
            OpcodeId::TLOAD | OpcodeId::TSTORE => vec![Self::TSTORAGE],
            OpcodeId::MCOPY => vec![Self::MCOPY, Self::MEMORY_GAS, Self::MEMORY_COPIER_GAS],
            OpcodeId::PUSH0
            | OpcodeId::PUSH1
            | OpcodeId::PUSH2
            | OpcodeId::PUSH3
            | OpcodeId::PUSH4
            | OpcodeId::PUSH5
            | OpcodeId::PUSH6
            | OpcodeId::PUSH7
            | OpcodeId::PUSH8
            | OpcodeId::PUSH9
            | OpcodeId::PUSH10
            | OpcodeId::PUSH11
            | OpcodeId::PUSH12
            | OpcodeId::PUSH13
            | OpcodeId::PUSH14
            | OpcodeId::PUSH15
            | OpcodeId::PUSH16
            | OpcodeId::PUSH17
            | OpcodeId::PUSH18
            | OpcodeId::PUSH19
            | OpcodeId::PUSH20
            | OpcodeId::PUSH21
            | OpcodeId::PUSH22
            | OpcodeId::PUSH23
            | OpcodeId::PUSH24
            | OpcodeId::PUSH25
            | OpcodeId::PUSH26
            | OpcodeId::PUSH27
            | OpcodeId::PUSH28
            | OpcodeId::PUSH29
            | OpcodeId::PUSH30
            | OpcodeId::PUSH31
            | OpcodeId::PUSH32 => vec![Self::PUSH],

            OpcodeId::DUP1
            | OpcodeId::DUP2
            | OpcodeId::DUP3
            | OpcodeId::DUP4
            | OpcodeId::DUP5
            | OpcodeId::DUP6
            | OpcodeId::DUP7
            | OpcodeId::DUP8
            | OpcodeId::DUP9
            | OpcodeId::DUP10
            | OpcodeId::DUP11
            | OpcodeId::DUP12
            | OpcodeId::DUP13
            | OpcodeId::DUP14
            | OpcodeId::DUP15
            | OpcodeId::DUP16 => vec![Self::DUP],

            OpcodeId::SWAP1
            | OpcodeId::SWAP2
            | OpcodeId::SWAP3
            | OpcodeId::SWAP4
            | OpcodeId::SWAP5
            | OpcodeId::SWAP6
            | OpcodeId::SWAP7
            | OpcodeId::SWAP8
            | OpcodeId::SWAP9
            | OpcodeId::SWAP10
            | OpcodeId::SWAP11
            | OpcodeId::SWAP12
            | OpcodeId::SWAP13
            | OpcodeId::SWAP14
            | OpcodeId::SWAP15
            | OpcodeId::SWAP16 => vec![Self::SWAP],

            OpcodeId::RETURN | OpcodeId::REVERT => {
                vec![
                    Self::RETURN_REVERT,
                    Self::MEMORY_GAS,
                    Self::PURE_MEMORY_GAS,
                    Self::END_CALL_2,
                ]
            }
            OpcodeId::INVALID(_) => {
                vec![Self::ERROR_INVALID_OPCODE]
            }
            OpcodeId::SHA3 => {
                vec![Self::KECCAK]
            }
            OpcodeId::BALANCE => {
                vec![Self::BALANCE]
            }
            OpcodeId::ORIGIN | OpcodeId::GASPRICE => vec![Self::TX_CONTEXT],
            OpcodeId::CALLER | OpcodeId::CALLVALUE | OpcodeId::CALLDATASIZE | OpcodeId::ADDRESS => {
                vec![Self::CALL_CONTEXT]
            }

            OpcodeId::EXTCODESIZE | OpcodeId::EXTCODEHASH => vec![Self::EXTCODEINFO],
            OpcodeId::EXTCODECOPY => {
                vec![Self::EXTCODECOPY, Self::MEMORY_GAS, Self::MEMORY_COPIER_GAS]
            }
            OpcodeId::RETURNDATASIZE => {
                vec![Self::RETURNDATASIZE]
            }
            OpcodeId::RETURNDATACOPY => {
                vec![
                    Self::RETURNDATACOPY,
                    Self::MEMORY_GAS,
                    Self::MEMORY_COPIER_GAS,
                ]
            }
            OpcodeId::BLOCKHASH => {
                vec![Self::BLOCKHASH]
            }
            OpcodeId::COINBASE
            | OpcodeId::TIMESTAMP
            | OpcodeId::NUMBER
            | OpcodeId::GASLIMIT
            | OpcodeId::CHAINID
            | OpcodeId::BASEFEE
            | OpcodeId::DIFFICULTY => vec![Self::PUBLIC_CONTEXT],
            OpcodeId::SELFBALANCE => {
                vec![Self::SELFBALANCE]
            }
            OpcodeId::SLOAD | OpcodeId::SSTORE => vec![Self::STORAGE],
            //LOG TOPIC LOG BYTES
            OpcodeId::LOG0 => {
                vec![
                    Self::LOG_BYTES,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::LOG_TOPIC_NUM_ADDR,
                ]
            }
            OpcodeId::LOG1 => {
                vec![
                    Self::LOG_BYTES,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::LOG_TOPIC_NUM_ADDR,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::LOG2 => {
                vec![
                    Self::LOG_BYTES,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::LOG_TOPIC_NUM_ADDR,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::LOG3 => {
                vec![
                    Self::LOG_BYTES,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::LOG_TOPIC_NUM_ADDR,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::LOG4 => {
                vec![
                    Self::LOG_BYTES,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::LOG_TOPIC_NUM_ADDR,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::CREATE => {
                log::warn!("Opcode CREATE Unsupported!");
                vec![Self::UNSUPPORTED]
            }
            OpcodeId::CREATE2 => {
                log::warn!("Opcode CREATE2 Unsupported!");
                vec![Self::UNSUPPORTED]
            }
            OpcodeId::CALL | OpcodeId::STATICCALL | OpcodeId::DELEGATECALL => {
                vec![
                    Self::CALL_1,
                    Self::CALL_2,
                    Self::CALL_3,
                    Self::CALL_4,
                    Self::CALL_5,
                    Self::CALL_6,
                    Self::CALL_7,
                ]
            }
            OpcodeId::CALLCODE => {
                log::warn!("Opcode CALLCODE Unsupported!");
                vec![Self::UNSUPPORTED]
            }
            OpcodeId::SELFDESTRUCT => {
                log::warn!("Opcode SELFDESTRUCT Unsupported!");
                vec![Self::UNSUPPORTED]
            }
        }
    }

    pub fn from_error(opcode: OpcodeId, exec_error: ExecError) -> Vec<Self> {
        match opcode {
            // example
            OpcodeId::JUMP | OpcodeId::JUMPI if matches!(exec_error, ExecError::InvalidJump) => {
                vec![Self::ERROR_INVALID_JUMP, Self::END_CALL_1, Self::END_CALL_2]
            }
            OpcodeId::BALANCE | OpcodeId::EXTCODEHASH | OpcodeId::EXTCODESIZE
                if matches!(exec_error, ExecError::OutOfGas(OogError::AccountAccess)) =>
            {
                vec![
                    Self::ERROR_OOG_ACCOUNT_ACCESS,
                    Self::END_CALL_1,
                    Self::END_CALL_2,
                ]
            }
            _ if matches!(exec_error, ExecError::OutOfGas(OogError::Constant)) => {
                vec![Self::ERROR_OOG_CONSTANT, Self::END_CALL_1, Self::END_CALL_2]
            }
            OpcodeId::LOG0 | OpcodeId::LOG1 | OpcodeId::LOG2 | OpcodeId::LOG3 | OpcodeId::LOG4
                if matches!(exec_error, ExecError::OutOfGas(OogError::Log)) =>
            {
                vec![
                    Self::ERROR_OOG_LOG,
                    Self::MEMORY_GAS,
                    Self::LOG_GAS,
                    Self::END_CALL_1,
                    Self::END_CALL_2,
                ]
            }
            OpcodeId::INVALID(_) if matches!(exec_error, ExecError::InvalidOpcode) => {
                vec![
                    Self::ERROR_INVALID_OPCODE,
                    Self::END_CALL_1,
                    Self::END_CALL_2,
                ]
            }
            _ if matches!(
                exec_error,
                ExecError::StackUnderflow | ExecError::StackOverflow
            ) =>
            {
                vec![
                    Self::ERROR_INVALID_STACK_POINTER,
                    Self::END_CALL_1,
                    Self::END_CALL_2,
                ]
            }
            _ => {
                unreachable!("{opcode} error not implement")
            }
        }
    }
}

#[cfg(test)]
mod test {
    /// Used in `mod test` under each execution gadget file
    /// Generate `TestCircuit` for the execution gadget
    macro_rules! generate_execution_gadget_test_circuit {
        () => {
            use super::*;
            use crate::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL, NUM_VERS};
            use crate::execution::ExecutionGadgets;
            use crate::table::{BitwiseTable, BytecodeTable, ExpTable, FixedTable, PublicTable, StateTable, ArithmeticTable, CopyTable};
            use crate::util::{assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes};
            use eth_types::evm_types::{OpcodeId, Stack};
            #[allow(unused_imports)]
            use eth_types::{GethExecStep, U256};
            use gadgets::dynamic_selector::DynamicSelectorChip;
            use gadgets::is_zero::IsZeroInstruction;
            use gadgets::is_zero_with_rotation::IsZeroWithRotationChip;
            use gadgets::util::Expr;
            use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
            use halo2_proofs::dev::MockProver;
            use halo2_proofs::halo2curves::bn256::Fr;
            use halo2_proofs::plonk::{Advice, Circuit, Column, Error};
            use halo2_proofs::poly::Rotation;

            #[derive(Clone, Default, Debug)]
            struct TestCircuit<F> {
                witness: Witness,
                _marker: PhantomData<F>,
            }
            impl<F: Field> Circuit<F> for TestCircuit<F> {
                type Config = ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
                type FloorPlanner = SimpleFloorPlanner;
                type Params = ();

                fn without_witnesses(&self) -> Self {
                    Self::default()
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let q_enable = meta.complex_selector();
                    let cnt = meta.advice_column();
                    let cnt_is_zero = IsZeroWithRotationChip::configure(
                        meta,
                        |meta| meta.query_selector(q_enable),
                        cnt,
                        None
                    );
                    let vers: [Column<Advice>; NUM_VERS] =
                        std::array::from_fn(|_| meta.advice_column());
                    let execution_state_selector = DynamicSelectorChip::configure(
                        meta,
                        |meta| {
                            let q_enable = meta.query_selector(q_enable);
                            let ans = cnt_is_zero.expr_at(meta, Rotation::cur());
                            q_enable * ans
                        },
                        vers[0..NUM_STATE_HI_COL].try_into().unwrap(),
                        vers[NUM_STATE_HI_COL..NUM_STATE_HI_COL + NUM_STATE_LO_COL]
                            .try_into()
                            .unwrap(),
                    );
                    let q_enable_bytecode = meta.complex_selector();
                    let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
                    let q_enable_state = meta.complex_selector();
                    let state_table = StateTable::construct(meta, q_enable_state);

                    let _instance_hash = PublicTable::construct_hash_instance_column(meta);
                    let public_table = PublicTable::construct(meta);
                    let q_enable_arithmetic = meta.complex_selector();
                    let arithmetic_table = ArithmeticTable::construct(meta, q_enable_arithmetic);
                    let q_enable_copy = meta.complex_selector();
                    let copy_table = CopyTable::construct(meta, q_enable_copy);
                    let q_enable_bitwise = meta.complex_selector();
                    let bitwise_table = BitwiseTable::construct(meta, q_enable_bitwise);
                    let fixed_table = FixedTable::construct(meta);
                    let q_first_exec_state = meta.selector();
                    let exp_table = ExpTable::construct(meta);
                    let config = ExecutionConfig {
                        q_first_exec_state,
                        q_enable,
                        block_idx: meta.advice_column(),
                        tx_idx: meta.advice_column(),
                        tx_is_create: meta.advice_column(),
                        call_id: meta.advice_column(),
                        code_addr: meta.advice_column(),
                        pc: meta.advice_column(),
                        opcode: meta.advice_column(),
                        cnt,
                        vers,
                        cnt_is_zero,
                        execution_state_selector,
                        bytecode_table,
                        state_table,
                        arithmetic_table,
                        copy_table,
                        bitwise_table,
                        public_table,
                        fixed_table,
                        exp_table,
                    };
                    let gadget = new();
                    meta.create_gate("TEST", |meta| {
                        let constraints = gadget.get_constraints(&config, meta);
                        if constraints.is_empty() {
                            return vec![("placeholder due to no constraint".into(), 0u8.expr())];
                        }
                        let q_enable = meta.query_selector(q_enable);
                        let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                        let condition = q_enable * cnt_is_zero;
                        constraints
                            .into_iter()
                            .map(|(s, e)| (s, condition.clone() * e))
                            .collect::<Vec<(String, Expression<F>)>>()
                    });
                    config
                }

                fn synthesize(
                    &self,
                    config: Self::Config,
                    mut layouter: impl Layouter<F>,
                ) -> Result<(), Error> {
                    layouter.assign_region(
                        || "test",
                        |mut region| {
                            region.name_column(|| "CORE_block_idx", config.block_idx);
                            region.name_column(|| "CORE_tx_idx", config.tx_idx);
                            region.name_column(|| "CORE_tx_is_create", config.tx_is_create);
                            region.name_column(|| "CORE_call_id", config.call_id);
                            region.name_column(|| "CORE_code_addr", config.code_addr);
                            region.name_column(|| "CORE_pc", config.pc);
                            region.name_column(|| "CORE_opcode", config.opcode);
                            region.name_column(|| "CORE_cnt", config.cnt);
                            for i in 0..NUM_VERS {
                                region.name_column(|| format!("CORE_vers_{}", i), config.vers[i]);
                            }
                            config
                                .cnt_is_zero
                                .annotate_columns_in_region(&mut region, "CORE_cnt_is_zero");
                            config.q_first_exec_state.enable(&mut region, ExecutionGadgets::<NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows::<F>().0)?;
                            for (offset, row) in self.witness.core.iter().enumerate() {
                                let cnt_is_zero: IsZeroWithRotationChip<F> =
                                    IsZeroWithRotationChip::construct(config.cnt_is_zero);
                                assign_advice_or_fixed_with_u256(
                                        &mut region,
                                        offset,
                                        &row.block_idx,
                                        config.block_idx,
                                )?;
                                assign_advice_or_fixed_with_u256(
                                    &mut region,
                                    offset,
                                    &row.tx_idx,
                                    config.tx_idx,
                                )?;
                                assign_advice_or_fixed_with_u256(
                                    &mut region,
                                    offset,
                                    &row.tx_is_create,
                                    config.tx_is_create,
                                )?;
                                assign_advice_or_fixed_with_u256(
                                    &mut region,
                                    offset,
                                    &row.call_id,
                                    config.call_id,
                                )?;
                                assign_advice_or_fixed_with_u256(
                                    &mut region,
                                    offset,
                                    &row.code_addr,
                                    config.code_addr,
                                )?;
                                assign_advice_or_fixed_with_u256(&mut region, offset, &row.pc, config.pc)?;
                                assign_advice_or_fixed_with_u256(
                                    &mut region,
                                    offset,
                                    &row.opcode.as_u8().into(),
                                    config.opcode,
                                )?;
                                assign_advice_or_fixed_with_u256(&mut region, offset, &row.cnt, config.cnt)?;
                                for i in 0 .. NUM_VERS {
                                    assign_advice_or_fixed_with_u256(&mut region,offset,&row[i].unwrap_or_default(),config.vers[i])?;
                                };
                                cnt_is_zero.assign(
                                    &mut region,
                                    offset,
                                    Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                                        &row.cnt,
                                    ))),
                                )?;
                            }
                            let gadget: Box<
                                dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
                            > = new();
                            // only enable the row with cnt=0
                            let enabled_row = gadget.unusable_rows().0 + gadget.num_row() - 1;
                            config.q_enable.enable(&mut region, enabled_row)?;
                            Ok(())
                        },
                    )
                }
            }
            impl<F: Field> TestCircuit<F> {
                pub fn new(witness: Witness) -> Self {
                    Self {
                        witness,
                        _marker: PhantomData,
                    }
                }
            }
        };
    }
    /// Used in `fn text_xx()` under each execution gadget file
    /// Generate witness and mock prover for the execution gadget
    macro_rules! prepare_witness_and_prover {
        ($trace:expr, $current_state:expr, $padding_begin_row:expr, $padding_end_row:expr) => {{
            let gadget: Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> = new();
            let mut witness = Witness::default();
            let mut current_state_begin = $current_state.clone();
            current_state_begin.memory_chunk = current_state_begin.memory_chunk_prev;
            for _ in 0..gadget.unusable_rows().0 {
                witness
                    .core
                    .insert(0, $padding_begin_row(&current_state_begin));
            }
            let this_witness = gadget.gen_witness(&$trace, &mut $current_state);
            assert_eq!(gadget.num_row(), this_witness.core.len());
            witness.append(this_witness);
            let mut current_state_end = $current_state.clone();
            current_state_end.memory_chunk_prev = current_state_end.memory_chunk;
            for _ in 0..gadget.unusable_rows().1 {
                witness.core.push($padding_end_row(&current_state_end));
            }
            let k = 8;
            let instance = witness.get_public_instance();
            let circuit = TestCircuit::<Fr>::new(witness.clone());
            let prover = MockProver::run(k, &circuit, instance).unwrap();
            (witness, prover)
        }};
    }
    macro_rules! prepare_trace_step {
        ($pc:expr, $op:expr, $stack: expr) => {{
            GethExecStep {
                pc: $pc,
                op: $op,
                gas: 100,
                gas_cost: 1,
                refund: 0,
                depth: 1,
                error: None,
                stack: $stack,
                memory: Default::default(),
                storage: Default::default(),
            }
        }};
        ($pc:expr, $op:expr, $stack: expr, $error: expr) => {{
            GethExecStep {
                pc: $pc,
                op: $op,
                gas: 100,
                gas_cost: 1,
                refund: 0,
                depth: 1,
                error: $error,
                stack: $stack,
                memory: Default::default(),
                storage: Default::default(),
            }
        }};
    }

    pub(crate) use {
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
}
