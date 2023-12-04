pub mod add;
pub mod addmod;
pub mod and_or_xor;
pub mod begin_tx_1;
pub mod begin_tx_2;
pub mod byte;
pub mod call_context;
pub mod calldatacopy;
pub mod calldataload;
pub mod codecopy;
pub mod div_mod;
pub mod dup;
pub mod end_block;
pub mod end_padding;
pub mod eq;
pub mod exp;
pub mod extcodecopy;
pub mod gt;
pub mod iszero;
pub mod jump;
pub mod jumpdest;
pub mod jumpi;
pub mod keccak;
pub mod log_bytes;
pub mod log_bytes;
pub mod log_topic;
pub mod lt;
pub mod memory;
pub mod mul;
pub mod mulmod;
pub mod not;
pub mod pop;
pub mod public_context;
pub mod push;
pub mod return_revert;
pub mod returndatacopy;
pub mod returndatasize;
pub mod selfbalance;
pub mod sgt;
pub mod shr;
pub mod slt;
pub mod stop;
pub mod storage;
pub mod sub;
pub mod swap;
pub mod tx_context;

use crate::table::{extract_lookup_expression, BytecodeTable, LookupEntry, StateTable};
use crate::witness::public::Tag;
use crate::witness::WitnessExecHelper;
use crate::witness::{copy, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::dynamic_selector::DynamicSelectorConfig;
use gadgets::is_zero_with_rotation::IsZeroWithRotationConfig;
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
            crate::execution::add::new(),
            crate::execution::push::new(),
            crate::execution::stop::new(),
            crate::execution::end_block::new(),
            crate::execution::iszero::new(),
            crate::execution::and_or_xor::new(),
            crate::execution::not::new(),
            crate::execution::jump::new(),
            crate::execution::jumpi::new(),
            crate::execution::jumpdest::new(),
            crate::execution::public_context::new(),
            crate::execution::tx_context::new(),
            crate::execution::memory::new(),
            crate::execution::storage::new(),
            crate::execution::call_context::new(),
            crate::execution::calldataload::new(),
            crate::execution::calldatacopy::new(),
            crate::execution::eq::new(),
            crate::execution::lt::new(),
            crate::execution::gt::new(),
            crate::execution::slt::new(),
            crate::execution::sgt::new(),
            crate::execution::byte::new(),
            crate::execution::dup::new(),
            crate::execution::mul::new(),
            crate::execution::sub::new(),
            crate::execution::div_mod::new(),
            crate::execution::addmod::new(),
            crate::execution::mulmod::new(),
            crate::execution::keccak::new(),
            crate::execution::pop::new(),
            crate::execution::shr::new(),
            crate::execution::codecopy::new(),
            crate::execution::extcodecopy::new(),
            crate::execution::swap::new(),
            crate::execution::return_revert::new(),
            crate::execution::exp::new(),
            crate::execution::begin_tx_1::new(),
            crate::execution::begin_tx_2::new(),
            crate::execution::selfbalance::new(),
            crate::execution::returndatacopy::new(),
            crate::execution::returndatasize::new(),
            crate::execution::log_bytes::new(),
            crate::execution::log_bytes::new(),
        ]
    }};
}
use crate::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL, NUM_VERS};
use crate::util::ExpressionOutcome;
pub(crate) use get_every_execution_gadgets;

#[derive(Clone)]
pub(crate) struct ExecutionConfig<F, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> {
    pub(crate) q_enable: Selector,
    // witness column of transaction index
    pub(crate) tx_idx: Column<Advice>,
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

/// Delta for `Auxiliary`. That is, we have constraint of `X_cur - X_prev - X_delta = 0`
pub(crate) struct AuxiliaryDelta<F> {
    /// Delta of state stamp (counter) at the end of the execution state and the previous state
    pub(crate) state_stamp: Expression<F>,
    /// Delta of stack pointer at the end of the execution state and the previous state
    pub(crate) stack_pointer: Expression<F>,
    /// Delta of log stamp (counter) at the end of the execution state and the previous state
    pub(crate) log_stamp: Expression<F>,
    /// Delta of gas left at the end of the execution state and the previous state
    pub(crate) gas_left: Expression<F>,
    /// Delta of refund at the end of the execution state and the previous state
    pub(crate) refund: Expression<F>,
    /// Delta of memory usage in chunk at the end of the execution state and the previous state
    pub(crate) memory_chunk: Expression<F>,
    /// Delta of read only indicator (0/1) at the end of the execution state and the previous state
    pub(crate) read_only: Expression<F>,
}

impl<F: Field> Default for AuxiliaryDelta<F> {
    fn default() -> Self {
        Self {
            state_stamp: 0.expr(),
            stack_pointer: 0.expr(),
            log_stamp: 0.expr(),
            gas_left: 0.expr(),
            refund: 0.expr(),
            memory_chunk: 0.expr(),
            read_only: 0.expr(),
        }
    }
}

/// Outcome for single-purpose (SP) columns in core circuit. That is, we have constraint of `X_next - X_cur - delta = 0`
pub(crate) struct CoreSinglePurposeOutcome<F> {
    /// Delta of pc (program counter) at the next execution state and current execution state
    pub(crate) pc: ExpressionOutcome<F>,
    pub(crate) tx_idx: ExpressionOutcome<F>,
    pub(crate) call_id: ExpressionOutcome<F>,
    pub(crate) code_addr: ExpressionOutcome<F>,
}

impl<F: Field> Default for CoreSinglePurposeOutcome<F> {
    fn default() -> Self {
        Self {
            pc: ExpressionOutcome::Delta(0.expr()),
            tx_idx: ExpressionOutcome::Delta(0.expr()),
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
                meta.query_advice(self.vers[26], Rotation::prev()),
                meta.query_advice(self.vers[27], Rotation::prev()),
            ],
            [
                meta.query_advice(self.vers[28], Rotation::prev()),
                meta.query_advice(self.vers[29], Rotation::prev()),
            ],
            [
                meta.query_advice(self.vers[30], Rotation::prev()),
                meta.query_advice(self.vers[31], Rotation::prev()),
            ],
        );
        LookupEntry::Exp { base, index, power }
    }

    pub(crate) fn get_bit_op_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        num: usize,
    ) -> LookupEntry<F> {
        assert!(num < 32);
        LookupEntry::BitOp {
            value_1: meta.query_advice(self.vers[num], Rotation(-2)),
            value_2: meta.query_advice(self.vers[num], Rotation(-3)),
            result: meta.query_advice(self.vers[num], Rotation(-4)),
            tag: meta.query_advice(self.vers[25], Rotation(-1)),
        }
    }

    pub(crate) fn get_calldata_load_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        index: usize, // 0..31
        base_pointer: Expression<F>,
        base_stamp: Expression<F>,
        value: &Column<Advice>,
    ) -> LookupEntry<F> {
        assert!(index < 32);
        LookupEntry::State {
            tag: (state::Tag::CallData as u8).expr(),
            stamp: base_stamp + index.expr(),
            value_lo: meta.query_advice(*value, Rotation(-2)),
            call_id_contract_addr: meta.query_advice(self.call_id, Rotation(-2)),
            pointer_lo: base_pointer + index.expr(),
            value_hi: 0.expr(),
            pointer_hi: 0.expr(),
            is_write: 0.expr(),
        }
    }

    pub(crate) fn get_state_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        num: usize,
    ) -> LookupEntry<F> {
        assert!(num < 4);
        const WIDTH: usize = 8;
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
            meta.query_advice(self.vers[num * WIDTH + 0], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 1], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 2], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 3], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 4], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 5], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 6], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 7], Rotation::prev()),
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

    // insert_public_lookup insert public lookup ,6 columns in row prev(-2)
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub(crate) fn get_public_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (tag, tx_idx_or_number_diff, value_0, value_1, value_2, value_3) = (
            meta.query_advice(self.vers[26], Rotation(-2)),
            meta.query_advice(self.vers[27], Rotation(-2)),
            meta.query_advice(self.vers[28], Rotation(-2)),
            meta.query_advice(self.vers[29], Rotation(-2)),
            meta.query_advice(self.vers[30], Rotation(-2)),
            meta.query_advice(self.vers[31], Rotation(-2)),
        );
        LookupEntry::Public {
            tag,
            tx_idx_or_number_diff,
            values: [value_0, value_1, value_2, value_3],
        }
    }

    // insert_public_lookup insert public lookup ,6 columns in row prev(-2)
    /// +---+-------+-------+-------+------+-----------+
    /// |cnt| 8 col | 8 col | 8 col | 2 col | public lookup(6 col) |
    /// +---+-------+-------+-------+----------+
    /// | 2 | | | | | TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
    /// +---+-------+-------+-------+----------+
    pub(crate) fn get_public_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (tag, tx_idx_or_number_diff, value_0, value_1, value_2, value_3) = (
            meta.query_advice(self.vers[26], Rotation(-2)),
            meta.query_advice(self.vers[27], Rotation(-2)),
            meta.query_advice(self.vers[28], Rotation(-2)),
            meta.query_advice(self.vers[29], Rotation(-2)),
            meta.query_advice(self.vers[30], Rotation(-2)),
            meta.query_advice(self.vers[31], Rotation(-2)),
        );
        LookupEntry::Public {
            tag,
            tx_idx_or_number_diff,
            values: [value_0, value_1, value_2, value_3],
        }
    }

    pub(crate) fn get_copy_contraints(
        &self,
        src_type: copy::Tag,
        src_id: Expression<F>,
        src_pointer: Expression<F>,
        src_stamp: Expression<F>,
        dst_type: copy::Tag,
        dst_id: Expression<F>,
        dst_pointer: Expression<F>,
        dst_stamp: Expression<F>,
        len: Expression<F>,
        len_is_zero: Expression<F>,
        copy_lookup_entry: LookupEntry<F>,
    ) -> Vec<(String, Expression<F>)> {
        let (
            copy_lookup_src_type,
            copy_lookup_src_id,
            copy_lookup_src_pointer,
            copy_lookup_src_stamp,
            copy_lookup_dst_type,
            copy_lookup_dst_id,
            copy_lookup_dst_pointer,
            copy_lookup_dst_stamp,
            copy_lookup_length,
        ) = extract_lookup_expression!(copy, copy_lookup_entry);

        let mut constraints = vec![];
        constraints.extend([
            (
                format!("src_type of copy is {:?}", src_type),
                (1.expr() - len_is_zero.clone())
                    * (copy_lookup_src_type.clone() - (src_type as u64).expr())
                    + len_is_zero.clone() * copy_lookup_src_type,
            ),
            (
                format!("src_id of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_id.clone() - src_id)
                    + len_is_zero.clone() * copy_lookup_src_id,
            ),
            (
                format!("src_pointer of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_pointer.clone() - src_pointer)
                    + len_is_zero.clone() * copy_lookup_src_pointer,
            ),
            (
                format!("src_stamp of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_src_stamp.clone() - src_stamp)
                    + len_is_zero.clone() * copy_lookup_src_stamp,
            ),
            (
                format!("dst_type of copy is {:?}", dst_type),
                (1.expr() - len_is_zero.clone())
                    * (copy_lookup_dst_type.clone() - (dst_type as u64).expr())
                    + len_is_zero.clone() * copy_lookup_dst_type,
            ),
            (
                format!("dst_id of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_id.clone() - dst_id)
                    + len_is_zero.clone() * copy_lookup_dst_id,
            ),
            (
                format!("dst_pointer of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_pointer.clone() - dst_pointer)
                    + len_is_zero.clone() * copy_lookup_dst_pointer,
            ),
            (
                format!("dst_stamp of copy"),
                (1.expr() - len_is_zero.clone()) * (copy_lookup_dst_stamp.clone() - dst_stamp)
                    + len_is_zero.clone() * copy_lookup_dst_stamp,
            ),
            (format!("length of copy"), copy_lookup_length.expr() - len),
        ]);

        constraints
    }

    pub(crate) fn get_stack_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
        index: usize,
        prev_exec_state_row: usize,
        stack_pointer_delta: Expression<F>, // compare to that of previous state
        write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let (tag, stamp, _, _, call_id_contract_addr, pointer_hi, pointer_lo, is_write) =
            extract_lookup_expression!(state, entry);
        let Auxiliary {
            state_stamp,
            stack_pointer,
            ..
        } = self.get_auxiliary();
        vec![
            (
                format!("state lookup tag[{}] = stack", index),
                tag - (state::Tag::Stack as u8).expr(),
            ),
            (
                format!("state stamp for state lookup[{}]", index),
                stamp
                    - meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - index.expr(),
            ),
            (
                format!("state lookup call id[{}]", index),
                call_id_contract_addr - meta.query_advice(self.call_id, Rotation::cur()),
            ),
            (format!("pointer_hi (stack pointer)[{}]", index), pointer_hi),
            (
                format!("pointer_lo (stack pointer)[{}]", index),
                pointer_lo
                    - meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32))
                    - stack_pointer_delta,
            ),
            (
                format!("is_write[{}]", index),
                is_write - (write as u8).expr(),
            ),
        ]
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
        write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let (tag, stamp, _, _, call_id_contract_addr, pointer_hi, pointer_lo, is_write) =
            extract_lookup_expression!(state, entry);
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        vec![
            (
                format!("state lookup tag[{}] = Storage", index),
                tag - (state::Tag::Storage as u8).expr(),
            ),
            (
                format!("state stamp for state lookup[{}]", index),
                stamp
                    - meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - index.expr(),
            ),
            (
                format!("state lookup call id[{}]", index),
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
                is_write - (write as u8).expr(),
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
        write: bool,
        selector: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let constraints_raw = self.get_stack_constraints(
            meta,
            entry,
            index,
            prev_exec_state_row,
            stack_pointer_delta,
            write,
        );

        let mut res: Vec<(String, Expression<F>)> = constraints_raw
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
        write: bool,
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
            write,
        );

        let mut res: Vec<(String, Expression<F>)> = constraints_raw
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
        write: bool,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = self.get_call_context_constraints(
            meta,
            entry.clone(),
            index,
            prev_exec_state_row,
            write,
            (state::CallContextTag::ReturnDataCallId as u8).expr(),
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
        write: bool,
        call_context_tag: Expression<F>,
        call_id: Expression<F>,
    ) -> Vec<(String, Expression<F>)> {
        let (tag, stamp, _, _, call_id_contract_addr, pointer_hi, pointer_lo, is_write) =
            extract_lookup_expression!(state, entry);
        let Auxiliary { state_stamp, .. } = self.get_auxiliary();
        vec![
            (
                format!("state lookup tag[{}] = CallContext", index),
                tag - (state::Tag::CallContext as u8).expr(),
            ),
            (
                format!("state stamp for state lookup[{}]", index),
                stamp
                    - meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - index.expr(),
            ),
            (
                format!("call id[{}]", index),
                call_id_contract_addr - call_id,
            ),
            (
                format!("pointer_hi (CallContext pointer)[{}]", index),
                pointer_hi,
            ),
            (
                format!("pointer_lo (CallContext pointer)[{}]", index),
                pointer_lo - call_context_tag,
            ),
            (
                format!("is_write[{}]", index),
                is_write - (write as u8).expr(),
            ),
        ]
    }

    pub(crate) fn get_bytecode_full_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (addr, pc, opcode, not_code, value_hi, value_lo, cnt, is_push) = (
            meta.query_advice(self.vers[24], Rotation::prev()),
            meta.query_advice(self.vers[25], Rotation::prev()),
            meta.query_advice(self.vers[26], Rotation::prev()),
            meta.query_advice(self.vers[27], Rotation::prev()),
            meta.query_advice(self.vers[28], Rotation::prev()),
            meta.query_advice(self.vers[29], Rotation::prev()),
            meta.query_advice(self.vers[30], Rotation::prev()),
            meta.query_advice(self.vers[31], Rotation::prev()),
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

    pub(crate) fn get_arithmetic_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3, tag) = (
            meta.query_advice(self.vers[0], Rotation(-2)),
            meta.query_advice(self.vers[1], Rotation(-2)),
            meta.query_advice(self.vers[2], Rotation(-2)),
            meta.query_advice(self.vers[3], Rotation(-2)),
            meta.query_advice(self.vers[4], Rotation(-2)),
            meta.query_advice(self.vers[5], Rotation(-2)),
            meta.query_advice(self.vers[6], Rotation(-2)),
            meta.query_advice(self.vers[7], Rotation(-2)),
            meta.query_advice(self.vers[8], Rotation(-2)),
        );
        LookupEntry::Arithmetic {
            tag,
            values: [hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3],
        }
    }

    pub(crate) fn get_copy_padding_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            len,
        ) = (
            meta.query_advice(self.vers[9], Rotation(-2)),
            meta.query_advice(self.vers[10], Rotation(-2)),
            meta.query_advice(self.vers[11], Rotation(-2)),
            meta.query_advice(self.vers[12], Rotation(-2)),
            meta.query_advice(self.vers[13], Rotation(-2)),
            meta.query_advice(self.vers[14], Rotation(-2)),
            meta.query_advice(self.vers[15], Rotation(-2)),
            meta.query_advice(self.vers[16], Rotation(-2)),
            meta.query_advice(self.vers[17], Rotation(-2)),
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
            len,
        }
    }

    pub(crate) fn get_copy_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            len,
        ) = (
            meta.query_advice(self.vers[0], Rotation(-2)),
            meta.query_advice(self.vers[1], Rotation(-2)),
            meta.query_advice(self.vers[2], Rotation(-2)),
            meta.query_advice(self.vers[3], Rotation(-2)),
            meta.query_advice(self.vers[4], Rotation(-2)),
            meta.query_advice(self.vers[5], Rotation(-2)),
            meta.query_advice(self.vers[6], Rotation(-2)),
            meta.query_advice(self.vers[7], Rotation(-2)),
            meta.query_advice(self.vers[8], Rotation(-2)),
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
            len,
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

    #[allow(unused)]
    pub(crate) fn get_auxiliary_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        prev_exec_state_row: usize,
        delta: AuxiliaryDelta<F>,
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
        vec![
            (
                "state stamp cur - prev - delta".into(),
                meta.query_advice(state_stamp, Rotation::cur())
                    - meta.query_advice(state_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - delta.state_stamp,
            ),
            (
                "stack pointer cur - prev - delta".into(),
                meta.query_advice(stack_pointer, Rotation::cur())
                    - meta.query_advice(stack_pointer, Rotation(-1 * prev_exec_state_row as i32))
                    - delta.stack_pointer,
            ),
            (
                "log stamp cur - prev - delta".into(),
                meta.query_advice(log_stamp, Rotation::cur())
                    - meta.query_advice(log_stamp, Rotation(-1 * prev_exec_state_row as i32))
                    - delta.log_stamp,
            ),
            (
                "read only cur - prev - delta".into(),
                meta.query_advice(read_only, Rotation::cur())
                    - meta.query_advice(read_only, Rotation(-1 * prev_exec_state_row as i32))
                    - delta.read_only,
            ),
            //todo other auxiliary
        ]
    }

    pub(crate) fn get_core_single_purpose_constraints(
        &self,
        meta: &mut VirtualCells<F>,
        delta: CoreSinglePurposeOutcome<F>,
    ) -> Vec<(String, Expression<F>)> {
        vec![
            (
                "pc next".into(),
                delta.pc.into_constraint(
                    meta.query_advice(self.pc, Rotation::next()),
                    meta.query_advice(self.pc, Rotation::cur()),
                ),
            ),
            (
                "tx_idx next".into(),
                delta.tx_idx.into_constraint(
                    meta.query_advice(self.tx_idx, Rotation::next()),
                    meta.query_advice(self.tx_idx, Rotation::cur()),
                ),
            ),
            (
                "call_id next".into(),
                delta.call_id.into_constraint(
                    meta.query_advice(self.call_id, Rotation::next()),
                    meta.query_advice(self.call_id, Rotation::cur()),
                ),
            ),
            (
                "code_addr next".into(),
                delta.code_addr.into_constraint(
                    meta.query_advice(self.code_addr, Rotation::next()),
                    meta.query_advice(self.code_addr, Rotation::cur()),
                ),
            ),
        ]
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
pub(crate) struct ExecutionGadgets<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    config: ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadgets<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        config: ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    ) -> Self {
        let gadgets: Vec<Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>> =
            get_every_execution_gadgets!();

        let mut lookups_to_merge = vec![];
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
        // todo
        // merge lookups from all gadgets
        // currently there is no merge
        #[cfg(not(feature = "no_intersubcircuit_lookup"))]
        for (string, lookup, execution_state) in lookups_to_merge {
            match lookup {
                LookupEntry::BytecodeFull { .. } | LookupEntry::State { .. } => {
                    meta.lookup_any(string, |meta| {
                        let q_enable = meta.query_selector(config.q_enable);
                        let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                        let execution_state_selector = config.execution_state_selector.selector(
                            meta,
                            execution_state as usize,
                            Rotation::cur(),
                        );
                        let condition = q_enable.clone() * cnt_is_zero * execution_state_selector;
                        let v = match lookup {
                            LookupEntry::BytecodeFull { .. } => {
                                config.bytecode_table.get_lookup_vector(meta, lookup)
                            }
                            LookupEntry::State { .. } => {
                                config.state_table.get_lookup_vector(meta, lookup)
                            }
                            _ => unreachable!(),
                        };
                        v.into_iter()
                            .map(|(left, right)| (condition.clone() * left, right))
                            .collect()
                    });
                }
                _ => (),
            };
        }
        ExecutionGadgets { config }
    }

    pub(crate) fn unusable_rows() -> (usize, usize) {
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
    END_BLOCK,
    // opcode/operation successful states
    STOP,
    ADD,
    MUL,
    SUB,
    EXP,
    DIV_MOD,
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
    TX_CONTEXT,
    MEMORY,
    STORAGE,
    CALL_CONTEXT,
    CALLDATALOAD,
    CALLDATACOPY,
    //CALLDATA_FROMPUBLIC,
    LOG_BYTES,
    LOG_TOPIC,
    EQ,
    LT,
    GT,
    SLT,
    SGT,
    DUP,
    SWAP,
    BYTE,
    RETURNDATASIZE,
    RETURN_REVERT,
    SHR,
    KECCAK,
    CODECOPY,
    EXTCODECOPY,
    SELFBALANCE,
    RETURNDATACOPY,
}

impl ExecutionState {
    // a mapping from opcode to execution state(s)
    pub fn from_opcode(opcode: OpcodeId) -> Vec<Self> {
        match opcode {
            OpcodeId::STOP => vec![Self::STOP],
            OpcodeId::ADD => vec![Self::ADD],
            OpcodeId::MUL => vec![Self::MUL],
            OpcodeId::SUB => vec![Self::SUB],
            OpcodeId::DIV | OpcodeId::MOD => vec![Self::DIV_MOD],
            OpcodeId::SDIV => {
                todo!()
            }
            OpcodeId::SMOD => {
                todo!()
            }
            OpcodeId::ADDMOD => vec![Self::ADDMOD],
            OpcodeId::MULMOD => vec![Self::MULMOD],
            OpcodeId::EXP => {
                vec![Self::EXP]
            }
            OpcodeId::SIGNEXTEND => {
                todo!()
            }
            OpcodeId::LT => vec![Self::LT],
            OpcodeId::GT => vec![Self::GT],
            OpcodeId::SLT => vec![Self::SLT],
            OpcodeId::SGT => vec![Self::SGT],
            OpcodeId::EQ => vec![Self::EQ],
            OpcodeId::ISZERO => vec![Self::ISZERO],
            OpcodeId::AND | OpcodeId::OR | OpcodeId::XOR => vec![Self::AND_OR_XOR],
            OpcodeId::NOT => vec![Self::NOT],
            OpcodeId::BYTE => vec![Self::BYTE],
            OpcodeId::CALLDATALOAD => vec![Self::CALLDATALOAD],
            OpcodeId::CALLDATACOPY => vec![Self::CALLDATACOPY],
            OpcodeId::CODESIZE => {
                todo!()
            }
            OpcodeId::CODECOPY => {
                vec![Self::CODECOPY]
            }
            OpcodeId::SHL => {
                todo!()
            }
            OpcodeId::SHR => {
                vec![Self::SHR]
            }
            OpcodeId::SAR => {
                todo!()
            }
            OpcodeId::POP => {
                vec![Self::POP]
            }
            OpcodeId::MLOAD | OpcodeId::MSTORE | OpcodeId::MSTORE8 => vec![Self::MEMORY],
            OpcodeId::JUMP => vec![Self::JUMP],
            OpcodeId::JUMPI => vec![Self::JUMPI],
            OpcodeId::PC => {
                todo!()
            }
            OpcodeId::MSIZE => {
                todo!()
            }
            OpcodeId::JUMPDEST => vec![Self::JUMPDEST],

            OpcodeId::PUSH1
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
                vec![Self::RETURN_REVERT]
            }
            OpcodeId::INVALID(_) => {
                todo!()
            }
            OpcodeId::SHA3 => {
                vec![Self::KECCAK]
            }
            OpcodeId::ADDRESS => {
                todo!()
            }
            OpcodeId::BALANCE => {
                todo!()
            }
            OpcodeId::ORIGIN | OpcodeId::GASPRICE => vec![Self::TX_CONTEXT],
            OpcodeId::CALLER | OpcodeId::CALLVALUE | OpcodeId::CALLDATASIZE => {
                vec![Self::CALL_CONTEXT]
            }

            OpcodeId::EXTCODESIZE => {
                todo!()
            }
            OpcodeId::EXTCODECOPY => {
                vec![Self::EXTCODECOPY]
            }
            OpcodeId::EXTCODEHASH => {
                todo!()
            }
            OpcodeId::RETURNDATASIZE => {
                todo!()
            }
            OpcodeId::RETURNDATACOPY => {
                vec![Self::RETURNDATACOPY]
            }
            OpcodeId::BLOCKHASH => {
                todo!()
            }
            OpcodeId::COINBASE
            | OpcodeId::TIMESTAMP
            | OpcodeId::NUMBER
            | OpcodeId::GASLIMIT
            | OpcodeId::CHAINID
            | OpcodeId::BASEFEE => vec![Self::PUBLIC_CONTEXT],
            OpcodeId::DIFFICULTY => {
                todo!()
            }
            OpcodeId::SELFBALANCE => {
                vec![Self::SELFBALANCE]
            }
            OpcodeId::SLOAD | OpcodeId::SSTORE => vec![Self::STORAGE],
            OpcodeId::GAS => {
                todo!()
            }
            //LOG TOPIC LOG BYTES
            OpcodeId::LOG0 => {
                vec![Self::LOG_BYTES]
            }
            OpcodeId::LOG1 => {
                vec![Self::LOG_BYTES, Self::LOG_TOPIC]
            }
            OpcodeId::LOG2 => {
                vec![Self::LOG_BYTES, Self::LOG_TOPIC, Self::LOG_TOPIC]
            }
            OpcodeId::LOG3 => {
                vec![
                    Self::LOG_BYTES,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::LOG4 => {
                vec![
                    Self::LOG_BYTES,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                    Self::LOG_TOPIC,
                ]
            }
            OpcodeId::CREATE => {
                todo!()
            }
            OpcodeId::CREATE2 => {
                todo!()
            }
            OpcodeId::CALL => {
                todo!()
            }
            OpcodeId::CALLCODE => {
                todo!()
            }
            OpcodeId::DELEGATECALL => {
                todo!()
            }
            OpcodeId::STATICCALL => {
                todo!()
            }
            OpcodeId::SELFDESTRUCT => {
                todo!()
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
            use crate::table::{BytecodeTable, StateTable};
            use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes};
            use eth_types::evm_types::{OpcodeId, Stack};
            use eth_types::GethExecStep;
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
                    let config = ExecutionConfig {
                        q_enable,
                        tx_idx: meta.advice_column(),
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
                            region.name_column(|| "CORE_tx_idx", config.tx_idx);
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
                            for (offset, row) in self.witness.core.iter().enumerate() {
                                let cnt_is_zero: IsZeroWithRotationChip<F> =
                                    IsZeroWithRotationChip::construct(config.cnt_is_zero);
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.tx_idx,
                                    config.tx_idx,
                                )?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.call_id,
                                    config.call_id,
                                )?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.code_addr,
                                    config.code_addr,
                                )?;
                                assign_advice_or_fixed(&mut region, offset, &row.pc, config.pc)?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.opcode.as_u8().into(),
                                    config.opcode,
                                )?;
                                assign_advice_or_fixed(&mut region, offset, &row.cnt, config.cnt)?;
                                for (i, value) in [
                                    &row.vers_0,
                                    &row.vers_1,
                                    &row.vers_2,
                                    &row.vers_3,
                                    &row.vers_4,
                                    &row.vers_5,
                                    &row.vers_6,
                                    &row.vers_7,
                                    &row.vers_8,
                                    &row.vers_9,
                                    &row.vers_10,
                                    &row.vers_11,
                                    &row.vers_12,
                                    &row.vers_13,
                                    &row.vers_14,
                                    &row.vers_15,
                                    &row.vers_16,
                                    &row.vers_17,
                                    &row.vers_18,
                                    &row.vers_19,
                                    &row.vers_20,
                                    &row.vers_21,
                                    &row.vers_22,
                                    &row.vers_23,
                                    &row.vers_24,
                                    &row.vers_25,
                                    &row.vers_26,
                                    &row.vers_27,
                                    &row.vers_28,
                                    &row.vers_29,
                                    &row.vers_30,
                                    &row.vers_31,
                                ]
                                .into_iter()
                                .enumerate()
                                {
                                    assign_advice_or_fixed(
                                        &mut region,
                                        offset,
                                        &value.unwrap_or_default(),
                                        config.vers[i],
                                    )?;
                                }
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
            for _ in 0..gadget.unusable_rows().0 {
                witness.core.insert(0, $padding_begin_row(&$current_state));
            }
            let mut this_witness = gadget.gen_witness(&$trace, &mut $current_state);
            assert_eq!(gadget.num_row(), this_witness.core.len());
            witness.append(this_witness);
            for _ in 0..gadget.unusable_rows().1 {
                witness.core.push($padding_end_row(&$current_state));
            }
            let k = 8;
            let circuit = TestCircuit::<Fr>::new(witness.clone());
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
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
    }
    pub(crate) use {
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
}
