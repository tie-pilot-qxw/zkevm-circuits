use crate::arithmetic_circuit::{LOG_NUM_ARITHMETIC_TAG, NUM_OPERAND};
use crate::constant::{LOG_NUM_BITWISE_TAG, LOG_NUM_STATE_TAG, PUBLIC_NUM_VALUES};
use crate::witness::{arithmetic, state};
use crate::witness::{bitwise, copy, fixed};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Expression, Fixed, Instance, SecondPhase, Selector,
    VirtualCells,
};
use halo2_proofs::poly::Rotation;
use strum_macros::{AsRefStr, EnumVariantNames};

pub const SEPARATOR: &str = "-";
pub const ANNOTATE_SEPARATOR: &str = ",";
pub const BITWISE_NUM_OPERAND: usize = 3;

macro_rules! extract_lookup_expression {
    (state, $value:expr) => {
        match $value {
            LookupEntry::State {
                tag,
                stamp,
                value_hi,
                value_lo,
                call_id_contract_addr,
                pointer_hi,
                pointer_lo,
                is_write,
            } => (
                tag,
                stamp,
                value_hi,
                value_lo,
                call_id_contract_addr,
                pointer_hi,
                pointer_lo,
                is_write,
            ),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (storage, $value:expr) => {
        match $value {
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
            } => (
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
            ),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (bytecode, $value:expr) => {
        match $value {
            LookupEntry::BytecodeFull {
                addr,
                pc,
                opcode,
                not_code,
                value_hi,
                value_lo,
                cnt,
                is_push,
            } => (addr, pc, opcode, not_code, value_hi, value_lo, cnt, is_push),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (arithmetic, $value:expr) => {
        match $value {
            LookupEntry::Arithmetic { tag, values } => (tag, values),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (arithmetic_tiny, $value:expr) => {
        match $value {
            LookupEntry::ArithmeticTiny { tag, values } => (tag, values),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (fixed, $value:expr) => {
        todo!()
    };
    (copy, $value:expr) => {
        match $value {
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
            } => (
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
            ),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (exp, $value:expr) => {
        match $value {
            LookupEntry::Exp { base, index, power } => (base, index, power),
            _ => panic!(""),
        }
    };
    (public, $value:expr) => {
        match $value {
            LookupEntry::Public {
                tag,
                tx_idx_or_number_diff,
                values,
            } => (tag, tx_idx_or_number_diff, values),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (bitwise, $value:expr) => {
        match $value {
            LookupEntry::Bitwise { tag, acc, sum_2 } => (tag, acc, sum_2),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (cnt, $value: expr) => {
        match $value {
            LookupEntry::StampCnt { tag, cnt } => (tag, cnt),
            _ => panic!("Pattern doesn't match!"),
        }
    };
    (most_significant_byte_len, $value: expr) => {
        match $value {
            LookupEntry::MostSignificantByteLen { acc_2, index } => (acc_2, index),
            _ => panic!("Pattern doesn't match!"),
        }
    };
}
pub(crate) use extract_lookup_expression;

/// The table shared between Core Circuit and Stack Circuit
#[derive(Clone, Copy, Debug)]
pub struct StateTable {
    pub(crate) tag: BinaryNumberConfig<state::Tag, LOG_NUM_STATE_TAG>,
    pub(crate) stamp: Column<Advice>,
    pub(crate) value_hi: Column<Advice>,
    pub(crate) value_lo: Column<Advice>,
    pub(crate) call_id_contract_addr: Column<Advice>,
    pub(crate) pointer_hi: Column<Advice>,
    pub(crate) pointer_lo: Column<Advice>,
    pub(crate) is_write: Column<Advice>,
    pub(crate) cnt: Column<Advice>,
    pub(crate) value_pre_lo: Column<Advice>,
    pub(crate) value_pre_hi: Column<Advice>,
    pub(crate) committed_value_lo: Column<Advice>,
    pub(crate) committed_value_hi: Column<Advice>,
}

impl StateTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Selector) -> Self {
        let stamp = meta.advice_column();
        let value_hi = meta.advice_column();
        let value_lo = meta.advice_column();
        let call_id_contract_addr = meta.advice_column();
        let pointer_hi = meta.advice_column();
        let pointer_lo = meta.advice_column();
        let is_write = meta.advice_column();
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let cnt = meta.advice_column();
        let value_pre_lo = meta.advice_column();
        let value_pre_hi = meta.advice_column();
        let committed_value_lo = meta.advice_column();
        let committed_value_hi = meta.advice_column();
        Self {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
            cnt,
            value_pre_lo,
            value_pre_hi,
            committed_value_lo,
            committed_value_hi,
        }
    }

    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_tag = self.tag.value(Rotation::cur())(meta);
        let table_stamp = meta.query_advice(self.stamp, Rotation::cur());
        let table_value_hi = meta.query_advice(self.value_hi, Rotation::cur());
        let table_value_lo = meta.query_advice(self.value_lo, Rotation::cur());
        let table_call_id_contract_addr =
            meta.query_advice(self.call_id_contract_addr, Rotation::cur());
        let table_pointer_hi = meta.query_advice(self.pointer_hi, Rotation::cur());
        let table_pointer_lo = meta.query_advice(self.pointer_lo, Rotation::cur());
        let table_is_write = meta.query_advice(self.is_write, Rotation::cur());
        let table_cnt = meta.query_advice(self.cnt, Rotation::cur());
        let table_value_pre_lo = meta.query_advice(self.value_pre_lo, Rotation::cur());
        let table_value_pre_hi = meta.query_advice(self.value_pre_hi, Rotation::cur());
        let table_committed_value_lo = meta.query_advice(self.committed_value_lo, Rotation::cur());
        let table_committed_value_hi = meta.query_advice(self.committed_value_hi, Rotation::cur());

        match entry {
            LookupEntry::State {
                tag,
                stamp,
                value_hi,
                value_lo,
                call_id_contract_addr,
                pointer_hi,
                pointer_lo,
                is_write,
            } => {
                vec![
                    (tag, table_tag),
                    (stamp, table_stamp),
                    (value_hi, table_value_hi),
                    (value_lo, table_value_lo),
                    (call_id_contract_addr, table_call_id_contract_addr),
                    (pointer_hi, table_pointer_hi),
                    (pointer_lo, table_pointer_lo),
                    (is_write, table_is_write),
                ]
            }
            LookupEntry::StampCnt { tag, cnt } => {
                vec![(tag, table_tag), (cnt, table_cnt)]
            }
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
            } => {
                vec![
                    (tag, table_tag),
                    (stamp, table_stamp),
                    (value_hi, table_value_hi),
                    (value_lo, table_value_lo),
                    (call_id_contract_addr, table_call_id_contract_addr),
                    (key_hi, table_pointer_hi),
                    (key_lo, table_pointer_lo),
                    (is_write, table_is_write),
                    (value_pre_hi, table_value_pre_hi),
                    (value_pre_lo, table_value_pre_lo),
                    (committed_value_hi, table_committed_value_hi),
                    (committed_value_lo, table_committed_value_lo),
                ]
            }
            _ => {
                panic!("Not state lookup!")
            }
        }
    }
}

/// The table shared between Core Circuit and Bytecode Circuit
#[derive(Clone, Copy, Debug)]
pub struct BytecodeTable<F> {
    /// the contract address of the bytecodes
    pub addr: Column<Advice>,
    /// the index that program counter points to
    pub pc: Column<Advice>,
    /// bytecode, operation code or pushed value
    pub bytecode: Column<Advice>,
    /// pushed value, high 128 bits
    pub value_hi: Column<Advice>,
    /// pushed value, lo 128 bits
    pub value_lo: Column<Advice>,
    /// push opcode's cnt
    pub cnt: Column<Advice>,
    /// is_zero of push opcode's cnt. iff it is zero at prev row, this row is code.
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
}

impl<F: Field> BytecodeTable<F> {
    pub fn construct(meta: &mut ConstraintSystem<F>, q_enable: Selector) -> Self {
        let cnt = meta.advice_column();
        let is_not_zero = Some(meta.advice_column());
        let cnt_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            cnt,
            is_not_zero,
        );
        Self {
            addr: meta.advice_column(),
            pc: meta.advice_column(),
            bytecode: meta.advice_column(),
            value_hi: meta.advice_column(),
            value_lo: meta.advice_column(),
            cnt,
            cnt_is_zero,
        }
    }

    pub fn get_lookup_vector(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_addr = meta.query_advice(self.addr, Rotation::cur());
        let table_pc = meta.query_advice(self.pc, Rotation::cur());
        let table_bytecode = meta.query_advice(self.bytecode, Rotation::cur());
        let table_not_code = 1.expr() - self.cnt_is_zero.expr_at(meta, Rotation::prev());
        let table_value_hi = meta.query_advice(self.value_hi, Rotation::cur());
        let table_value_lo = meta.query_advice(self.value_lo, Rotation::cur());
        let table_cnt = meta.query_advice(self.cnt, Rotation::cur());
        let table_is_push = 1.expr() - self.cnt_is_zero.expr_at(meta, Rotation::cur());

        match entry {
            LookupEntry::Bytecode { addr, pc, opcode } => {
                //let not_code = 0.expr();
                vec![
                    (addr, table_addr),
                    (pc, table_pc),
                    (opcode, table_bytecode),
                    //(not_code, table_not_code),
                ]
            }
            LookupEntry::BytecodeFull {
                addr,
                pc,
                opcode,
                not_code,
                value_hi,
                value_lo,
                cnt,
                is_push,
            } => {
                vec![
                    (addr, table_addr),
                    (pc, table_pc),
                    (opcode, table_bytecode),
                    (not_code, table_not_code),
                    (value_hi, table_value_hi),
                    (value_lo, table_value_lo),
                    (cnt, table_cnt),
                    (is_push, table_is_push),
                ]
            }
            _ => panic!("Not bytecode lookup!"),
        }
    }
}

impl<F: Field> BytecodeTable<F> {
    // construct_addr_bytecode_instance_column init two instance column
    pub fn construct_addr_bytecode_instance_column(
        meta: &mut ConstraintSystem<F>,
    ) -> (Column<Instance>, Column<Instance>) {
        let addr_instance_column = meta.instance_column();
        let bytecode_instance_column = meta.instance_column();
        (addr_instance_column, bytecode_instance_column)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedTable {
    pub tag: Column<Fixed>,
    pub values: [Column<Fixed>; 3],
}

impl FixedTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let table = Self {
            tag: meta.fixed_column(),
            values: [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ],
        };
        meta.annotate_lookup_any_column(table.tag, || "FIXED_Table_Tag");
        meta.annotate_lookup_any_column(table.values[0], || "FIXED_Table_Value0");
        meta.annotate_lookup_any_column(table.values[1], || "FIXED_Table_Value1");
        meta.annotate_lookup_any_column(table.values[2], || "FIXED_Table_Value2");
        table
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>, // fixed 类型，
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_tag = meta.query_fixed(self.tag, Rotation::cur());
        let table_value_0 = meta.query_fixed(self.values[0], Rotation::cur());
        let table_value_1 = meta.query_fixed(self.values[1], Rotation::cur());
        let table_value_2 = meta.query_fixed(self.values[2], Rotation::cur());

        match entry {
            LookupEntry::Fixed { tag, values } => {
                vec![
                    (tag, table_tag),
                    (values[0].clone(), table_value_0),
                    (values[1].clone(), table_value_1),
                    (values[2].clone(), table_value_2),
                ]
            }
            LookupEntry::U8(value) => {
                vec![
                    ((fixed::Tag::And as u8).expr(), table_tag),
                    (value, table_value_0),
                ]
            }
            LookupEntry::U10(value) => {
                vec![
                    (fixed::U10_TAG.expr(), table_value_1),
                    (value, table_value_2),
                ]
            }
            LookupEntry::U16(value) => {
                vec![(value, table_value_0)]
            }
            _ => panic!("Not fixed lookup"),
        }
    }
}

/// The table shared between Core Circuit and Arithmetic Circuit
#[derive(Clone, Copy, Debug)]
pub struct ArithmeticTable {
    /// Tag for arithmetic operation type
    pub tag: BinaryNumberConfig<arithmetic::Tag, LOG_NUM_ARITHMETIC_TAG>,
    /// The operands in one row, split to 2 (high and low 128-bit)
    pub operands: [[Column<Advice>; 2]; NUM_OPERAND],
    /// Row counter, decremented for rows in one execution state
    pub cnt: Column<Advice>,
}

impl ArithmeticTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Selector) -> Self {
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let cnt = meta.advice_column();
        let operands = std::array::from_fn(|_| [meta.advice_column(), meta.advice_column()]);
        Self { tag, cnt, operands }
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_tag = self.tag.value(Rotation::cur())(meta);
        let table_0_hi = meta.query_advice(self.operands[0][0], Rotation::cur());
        let table_0_lo = meta.query_advice(self.operands[0][1], Rotation::cur());
        let table_1_hi = meta.query_advice(self.operands[1][0], Rotation::cur());
        let table_1_lo = meta.query_advice(self.operands[1][1], Rotation::cur());
        let table_2_hi = meta.query_advice(self.operands[0][0], Rotation::prev());
        let table_2_lo = meta.query_advice(self.operands[0][1], Rotation::prev());
        let table_3_hi = meta.query_advice(self.operands[1][0], Rotation::prev());
        let table_3_lo = meta.query_advice(self.operands[1][1], Rotation::prev());
        match entry {
            LookupEntry::Arithmetic { tag, values } => {
                vec![
                    (tag.clone(), table_tag),
                    (values[0].clone(), table_0_hi),
                    (values[1].clone(), table_0_lo),
                    (values[2].clone(), table_1_hi),
                    (values[3].clone(), table_1_lo),
                    (values[4].clone(), table_2_hi),
                    (values[5].clone(), table_2_lo),
                    (values[6].clone(), table_3_hi),
                    (values[7].clone(), table_3_lo),
                ]
            }
            LookupEntry::ArithmeticShort { tag, values } => {
                vec![
                    (tag.clone(), table_tag),
                    (values[0].clone(), table_0_hi),
                    (values[1].clone(), table_0_lo),
                    (values[2].clone(), table_1_hi),
                    (values[3].clone(), table_1_lo),
                    (values[4].clone(), table_2_hi),
                    (values[5].clone(), table_2_lo),
                ]
            }
            LookupEntry::ArithmeticTiny { tag, values } => {
                vec![
                    (tag.clone(), table_tag),
                    (values[0].clone(), table_0_hi),
                    (values[1].clone(), table_0_lo),
                    (values[2].clone(), table_1_hi),
                    (values[3].clone(), table_1_lo),
                ]
            }
            _ => panic!("Not arithmetic lookup!"),
        }
    }
}

// The table shared between Core circuit and Copy circuit
#[derive(Clone, Copy, Debug)]
pub struct CopyTable {
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// src Tag of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    pub src_tag: BinaryNumberConfig<copy::Tag, LOG_NUM_STATE_TAG>,
    /// The source id, tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: Column<Advice>,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: Column<Advice>,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: Column<Advice>,
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// dst Tag of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    pub dst_tag: BinaryNumberConfig<copy::Tag, LOG_NUM_STATE_TAG>,
    /// The destination id, tx_idx for PublicLog, call_id for Memory, Calldata, Returndata
    pub dst_id: Column<Advice>,
    /// The destination pointer, for Calldata, Returndata, PublicLog means the index, for Memory means the address
    pub dst_pointer: Column<Advice>,
    /// The destination stamp, state stamp for Memory, Calldata, Returndata. As for PublicLog it means the log_stamp
    pub dst_stamp: Column<Advice>,
    /// The counter for one copy operation
    pub cnt: Column<Advice>,
    /// The length for one copy operation
    pub len: Column<Advice>,
    /// The accumulation value of bytes for one copy operation
    pub acc: Column<Advice>,
}
impl CopyTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Selector) -> Self {
        let src_id = meta.advice_column();
        let src_pointer = meta.advice_column();
        let src_stamp = meta.advice_column();
        let dst_id = meta.advice_column();
        let dst_pointer = meta.advice_column();
        let dst_stamp = meta.advice_column();
        let cnt = meta.advice_column();
        let len = meta.advice_column();
        let acc = meta.advice_column();
        let src_tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let dst_tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        return Self {
            src_id,
            src_pointer,
            src_stamp,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            src_tag,
            dst_tag,
            acc,
        };
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_src_id = meta.query_advice(self.src_id, Rotation::cur());
        let table_src_pointer = meta.query_advice(self.src_pointer, Rotation::cur());
        let table_src_stamp = meta.query_advice(self.src_stamp, Rotation::cur());
        let table_dst_id = meta.query_advice(self.dst_id, Rotation::cur());
        let table_dst_pointer = meta.query_advice(self.dst_pointer, Rotation::cur());
        let table_dst_stamp = meta.query_advice(self.dst_stamp, Rotation::cur());
        let table_cnt = meta.query_advice(self.cnt, Rotation::cur());
        let table_len = meta.query_advice(self.len, Rotation::cur());
        let table_acc = meta.query_advice(self.acc, Rotation::cur());
        let table_src_tag = self.src_tag.value(Rotation::cur())(meta);
        let table_dst_tag = self.dst_tag.value(Rotation::cur())(meta);
        match entry {
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
            } => {
                vec![
                    (src_type, table_src_tag),
                    (dst_type, table_dst_tag),
                    (src_id, table_src_id),
                    (src_pointer, table_src_pointer),
                    (src_stamp, table_src_stamp),
                    (dst_id, table_dst_id),
                    (dst_pointer, table_dst_pointer),
                    (dst_stamp, table_dst_stamp),
                    (cnt, table_cnt),
                    (len, table_len),
                    (acc, table_acc),
                ]
            }
            _ => panic!("NOT copy lookup"),
        }
    }
}

/// The table shared between Core Circuit and Public Circuit
#[derive(Clone, Copy, Debug)]
pub struct PublicTable {
    /// various public information tag, e.g. BlockNumber, TxFrom
    pub tag: Column<Instance>,
    /// tx_id (start from 1), except for tag=BlockHash, means recent block number diff (1...256)
    pub tx_idx_or_number_diff: Column<Instance>,
    pub values: [Column<Instance>; PUBLIC_NUM_VALUES],
}
impl PublicTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let tag = meta.instance_column();
        let tx_idx_or_number_diff = meta.instance_column();
        let values = std::array::from_fn(|_| meta.instance_column());
        Self {
            tag,
            tx_idx_or_number_diff,
            values,
        }
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_tag = meta.query_instance(self.tag, Rotation::cur());
        let table_tx_idx_or_number_diff =
            meta.query_instance(self.tx_idx_or_number_diff, Rotation::cur());
        let table_value_0 = meta.query_instance(self.values[0], Rotation::cur());
        let table_value_1 = meta.query_instance(self.values[1], Rotation::cur());
        let table_value_2 = meta.query_instance(self.values[2], Rotation::cur());
        let table_value_3 = meta.query_instance(self.values[3], Rotation::cur());
        match entry {
            LookupEntry::Public {
                tag,
                tx_idx_or_number_diff,
                values,
            } => {
                vec![
                    (tag, table_tag),
                    (tx_idx_or_number_diff, table_tx_idx_or_number_diff),
                    (values[0].clone(), table_value_0),
                    (values[1].clone(), table_value_1),
                    (values[2].clone(), table_value_2),
                    (values[3].clone(), table_value_3),
                ]
            }
            _ => panic!("Not public lookup!"),
        }
    }
}

/// The table shared between Core Circuit and Bitwise Circuit
#[derive(Clone, Copy, Debug)]
pub struct BitwiseTable {
    /// The operation tag, one of AND, OR
    pub tag: BinaryNumberConfig<bitwise::Tag, LOG_NUM_BITWISE_TAG>,
    /// The accumulation of bytes in one operation for each operand in one row
    pub acc_vec: [Column<Advice>; BITWISE_NUM_OPERAND],
    /// The sum of bytes in one operation of operand 2, used to compute byte opcode
    pub sum_2: Column<Advice>,
    pub index: Column<Advice>,
}

impl BitwiseTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Selector) -> Self {
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let acc_vec: [Column<Advice>; BITWISE_NUM_OPERAND] =
            std::array::from_fn(|_| meta.advice_column());
        let sum_2 = meta.advice_column();
        let index = meta.advice_column();
        Self {
            tag,
            acc_vec,
            sum_2,
            index,
        }
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_tag = self.tag.value(Rotation::cur())(meta);
        let table_acc_0 = meta.query_advice(self.acc_vec[0], Rotation::cur());
        let table_acc_1 = meta.query_advice(self.acc_vec[1], Rotation::cur());
        let table_acc_2 = meta.query_advice(self.acc_vec[2], Rotation::cur());
        let table_sum_2 = meta.query_advice(self.sum_2, Rotation::cur());
        let table_index = meta.query_advice(self.index, Rotation::cur());
        match entry {
            LookupEntry::Bitwise { tag, acc, sum_2 } => {
                vec![
                    (tag.clone(), table_tag),
                    (acc[0].clone(), table_acc_0),
                    (acc[1].clone(), table_acc_1),
                    (acc[2].clone(), table_acc_2),
                    (sum_2.clone(), table_sum_2),
                ]
            }
            LookupEntry::MostSignificantByteLen { acc_2, index } => {
                vec![
                    ((bitwise::Tag::Or as u8).expr(), table_tag),
                    (acc_2, table_acc_2),
                    (index, table_index),
                ]
            }
            _ => panic!("Not bitwise lookup!"),
        }
    }
}

/// The table shared between Core Circuit and Exp Circuit
#[derive(Clone, Copy, Debug)]
pub struct ExpTable {
    /// base in one row, split to 2 (high and low 128-bit)
    pub base: [Column<Advice>; 2],
    /// index in one row, split to 2 (high and low 128-bit)
    pub index: [Column<Advice>; 2],
    /// power in one row, split to 2 (high and low 128-bit)
    pub power: [Column<Advice>; 2],
}
impl ExpTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let base: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
        let index: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
        let power: [Column<Advice>; 2] = std::array::from_fn(|_| meta.advice_column());
        Self { base, index, power }
    }
    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_base_hi = meta.query_advice(self.base[0], Rotation::cur());
        let table_base_lo = meta.query_advice(self.base[1], Rotation::cur());
        let table_index_hi = meta.query_advice(self.index[0], Rotation::cur());
        let table_index_lo = meta.query_advice(self.index[1], Rotation::cur());
        let table_power_hi = meta.query_advice(self.power[0], Rotation::cur());
        let table_power_lo = meta.query_advice(self.power[1], Rotation::cur());
        match entry {
            LookupEntry::Exp { base, index, power } => {
                vec![
                    (base[0].clone(), table_base_hi),
                    (base[1].clone(), table_base_lo),
                    (index[0].clone(), table_index_hi),
                    (index[1].clone(), table_index_lo),
                    (power[0].clone(), table_power_hi),
                    (power[1].clone(), table_power_lo),
                ]
            }
            _ => panic!("Not exp lookup!"),
        }
    }
}

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    /// We replace it with output_hi, lo. It is not used anymore.
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
    // new columns to hold hash hi and lo 128 bits without RLC
    /// High 128 bits of the hash result
    pub output_hi: Column<Advice>,
    /// Low 128 bits of the hash result
    pub output_lo: Column<Advice>,
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            input_len: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            output_rlc: meta.advice_column_in(SecondPhase),
            output_hi: meta.advice_column(),
            output_lo: meta.advice_column(),
        }
    }

    pub fn get_lookup_vector<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        entry: LookupEntry<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let table_input_rlc = meta.query_advice(self.input_rlc, Rotation::cur());
        let table_input_len = meta.query_advice(self.input_len, Rotation::cur());
        let table_output_hi = meta.query_advice(self.output_hi, Rotation::cur());
        let table_output_lo = meta.query_advice(self.output_lo, Rotation::cur());
        match entry {
            LookupEntry::Keccak {
                input_rlc,
                input_len,
                output_hi,
                output_lo,
            } => {
                vec![
                    (input_rlc, table_input_rlc),
                    (input_len, table_input_len),
                    (output_hi, table_output_hi),
                    (output_lo, table_output_lo),
                ]
            }
            _ => panic!("Not keccak lookup!"),
        }
    }
}

/// Lookup structure. Use this structure to normalize the order of expressions inside lookup.
#[derive(Clone, Debug, EnumVariantNames, AsRefStr)]
pub enum LookupEntry<F> {
    // 0-255
    U8(Expression<F>),
    // 1-1024, not 0-1023
    U10(Expression<F>),
    U16(Expression<F>),
    /// Lookup to fixed table
    Fixed {
        /// Tag could be LogicAnd, LogicOr, or Bytecode (opcode, push cnt, is_high)
        tag: Expression<F>,
        /// Values in logic means operands, in Bytecode mean (opcode, push cnt, is_high)
        values: [Expression<F>; 3],
    },
    /// Lookup to state table, which contains read/write of stack, memory, storage,
    /// call context, call data, and return data
    State {
        /// Tag can be stack, memory, storage, call context, call data, and return data
        tag: Expression<F>,
        /// State stamp.
        stamp: Expression<F>,
        /// Value high 128 bits.
        value_hi: Expression<F>,
        /// Value low 128 bits.
        value_lo: Expression<F>,
        /// This item in storage means contract addr. In stack, memory, call context
        /// it means call id.
        call_id_contract_addr: Expression<F>,
        /// Point high is used for storage and means the key's high 128 bits.
        pointer_hi: Expression<F>,
        /// Point lo is used for storage and means the key's low 128 bits.
        /// It also means the pointer for stack, memory, call data, and return data.
        /// It also means the tag for call context.
        pointer_lo: Expression<F>,
        /// A boolean value to specify if the access record is a read or write.
        is_write: Expression<F>,
    },
    Storage {
        /// Tag can be stack, memory, storage, call context, call data, and return data
        tag: Expression<F>,
        /// State stamp.
        stamp: Expression<F>,
        /// Value high 128 bits.
        value_hi: Expression<F>,
        /// Value low 128 bits.
        value_lo: Expression<F>,
        /// This item in storage means contract addr. In stack, memory, call context
        /// it means call id.
        call_id_contract_addr: Expression<F>,
        /// Point high is used for storage and means the key's high 128 bits.
        key_hi: Expression<F>,
        /// Point lo is used for storage and means the key's low 128 bits.
        /// It also means the pointer for stack, memory, call data, and return data.
        /// It also means the tag for call context.
        key_lo: Expression<F>,
        /// A boolean value to specify if the access record is a read or write.
        is_write: Expression<F>,
        /// previous value high 128 bits.
        value_pre_lo: Expression<F>,
        /// previous value lo 128 bits.
        value_pre_hi: Expression<F>,
        /// committed value high 128 bits.
        committed_value_lo: Expression<F>,
        /// committed value lo 128 bits.
        committed_value_hi: Expression<F>,
    },
    /// Lookup to bytecode table that only involves addr, pc, and opcode
    Bytecode {
        /// Address of the contract
        addr: Expression<F>,
        /// Program counter or the index of bytecodes
        pc: Expression<F>,
        /// The opcode or bytecode
        opcode: Expression<F>,
    },
    /// Lookup to bytecode table (full mode), which contains all necessary columns
    BytecodeFull {
        /// Address of the contract
        addr: Expression<F>,
        /// Program counter or the index of bytecodes
        pc: Expression<F>,
        /// The opcode or bytecode
        opcode: Expression<F>,
        /// Whether this pc points to a code or a pushed value
        not_code: Expression<F>,
        /// Pushed value, high 128 bits (0 or non-push opcodes)
        value_hi: Expression<F>,
        /// Pushed value, low 128 bits (0 or non-push opcodes)
        value_lo: Expression<F>,
        /// Cnt of push, X in PUSHX. 0 for other opcodes
        cnt: Expression<F>,
        /// Whether this is push
        is_push: Expression<F>,
    },
    /// Lookup to copy table.
    Copy {
        /// The source type for the copy event.
        src_type: Expression<F>,
        /// The source ID for the copy event.
        src_id: Expression<F>,
        /// The source pointer (index or address depending on the type)
        src_pointer: Expression<F>,
        /// The source stamp (state stamp or N/A)
        src_stamp: Expression<F>,
        /// The destination type for the copy event.
        dst_type: Expression<F>,
        /// The destination ID for the copy event.
        dst_id: Expression<F>,
        /// The destination pointer (index or address depending on the type)
        dst_pointer: Expression<F>,
        /// The destination stamp (state stamp or log stamp)
        dst_stamp: Expression<F>,
        /// The counter for one copy operation
        cnt: Expression<F>,
        /// The length of the copy event
        len: Expression<F>,
        /// The accumulation of bytes in one copy
        acc: Expression<F>,
    },
    /// Lookup to arithmetic table.
    Arithmetic {
        /// Which arithmetic operation it is doing
        tag: Expression<F>,
        /// Operand 0-3 high and low 128 bits, order: [hi0,lo0,hi1,lo1,...]
        values: [Expression<F>; 8],
    },

    /// Lookup to arithmetic table.
    ArithmeticShort {
        /// Which arithmetic operation it is doing
        tag: Expression<F>,
        /// Operand 0-2 high and low 128 bits, order: [hi0,lo0,hi1,lo1,...]
        values: [Expression<F>; 6],
    },
    /// Lookup to arithmetic tiny table. This lookup only used 5 values
    ArithmeticTiny {
        tag: Expression<F>,
        values: [Expression<F>; 4],
    },
    /// Lookup to exp table
    Exp {
        base: [Expression<F>; 2],
        index: [Expression<F>; 2],
        power: [Expression<F>; 2],
    },
    /// Bitwise lookup operation, lookup to bitwise table
    Bitwise {
        /// Tag could be Nil, And, Or
        tag: Expression<F>,
        /// Three operands of 128-bit
        acc: [Expression<F>; 3],
        /// The sum of bytes for operand 2, used for BYTE opcode
        sum_2: Expression<F>,
    },
    /// MostSignificantByteLen lookup operation, lookup to bitwise table
    MostSignificantByteLen {
        /// acc_2 is operand_0, tag always OR
        acc_2: Expression<F>,
        /// index is most significant byte index
        index: Expression<F>,
    },
    /// Lookup to Public table
    Public {
        tag: Expression<F>,
        tx_idx_or_number_diff: Expression<F>,
        values: [Expression<F>; PUBLIC_NUM_VALUES],
    },
    /// Lookup to state table
    StampCnt {
        /// Tag is EndPadding
        tag: Expression<F>,
        /// cnt == stamp of state + 1
        cnt: Expression<F>,
    },
    Keccak {
        /// Byte array input as `RLC(reversed(input))`
        input_rlc: Expression<F>,
        /// Byte array input length
        input_len: Expression<F>,
        /// High 128 bits of the hash result
        output_hi: Expression<F>,
        /// Low 128 bits of the hash result
        output_lo: Expression<F>,
    },
}

impl<F: Field> LookupEntry<F> {
    /// 获取lookup entry的标识符，用于将不同的lookup归类。
    /// 标识符由两部分组成：来源+去向==》LookupEntry中所有表达式字段的标识符
    /// 和枚举元素的名称；LookupEntry中所有表达式的字段lookup的来源，枚举元
    /// 素的名称为去向（即去哪个table中进行查询，如State Entry则去StateTable
    /// 中查询，BytecodeFull则去BytecodeTable中去查询）
    /// Note：一定要加上去向，因为会存在不同类型Entry具有相同来源，如下
    /// ("lookup_bytecode_full", BytecodeFull { addr: Advice { query_index: 85, column_index: 48, rotation: Rotation(-1)
    // }, pc: Advice { query_index: 86, column_index: 49, rotation: Rotation(-1)
    // }, opcode: Advice { query_index: 87, column_index: 50, rotation: Rotation(-1)
    // }, not_code: Advice { query_index: 88, column_index: 51, rotation: Rotation(-1)
    // }, value_hi: Advice { query_index: 89, column_index: 52, rotation: Rotation(-1)
    // }, value_lo: Advice { query_index: 90, column_index: 53, rotation: Rotation(-1)
    // }, cnt: Advice { query_index: 91, column_index: 54, rotation: Rotation(-1)
    // }, is_push: Advice { query_index: 92, column_index: 55, rotation: Rotation(-1)
    // }
    // }, JUMPI), ("stack push or storage write", State { tag: Advice { query_index: 85, column_index: 48, rotation: Rotation(-1)
    // }, stamp: Advice { query_index: 86, column_index: 49, rotation: Rotation(-1)
    // }, value_hi: Advice { query_index: 87, column_index: 50, rotation: Rotation(-1)
    // }, value_lo: Advice { query_index: 88, column_index: 51, rotation: Rotation(-1)
    // }, call_id_contract_addr: Advice { query_index: 89, column_index: 52, rotation: Rotation(-1)
    // }, pointer_hi: Advice { query_index: 90, column_index: 53, rotation: Rotation(-1)
    // }, pointer_lo: Advice { query_index: 91, column_index: 54, rotation: Rotation(-1)
    // }, is_write: Advice { query_index: 92, column_index: 55, rotation: Rotation(-1)
    // }
    // }, STORAGE),
    /// JUMPI和STORAGE来源的元素完全相同，但需要使用不同的table进行lookup。
    pub fn identifier(&self) -> String {
        // 获取Entry所有表达式字段的标识符作为lookup的来源
        let mut strings = match self {
            LookupEntry::Bytecode { addr, pc, opcode } => {
                vec![addr.identifier(), pc.identifier(), opcode.identifier()]
            }
            LookupEntry::BytecodeFull {
                addr,
                pc,
                opcode,
                not_code,
                value_hi,
                value_lo,
                cnt,
                is_push,
            } => {
                vec![
                    addr.identifier(),
                    pc.identifier(),
                    opcode.identifier(),
                    not_code.identifier(),
                    value_hi.identifier(),
                    value_lo.identifier(),
                    cnt.identifier(),
                    is_push.identifier(),
                ]
            }
            LookupEntry::Fixed { tag, values } => {
                vec![
                    tag.identifier(),
                    values[0].identifier(),
                    values[1].identifier(),
                    values[2].identifier(),
                ]
            }
            LookupEntry::State {
                tag,
                stamp,
                value_hi,
                value_lo,
                call_id_contract_addr,
                pointer_hi,
                pointer_lo,
                is_write,
            } => {
                vec![
                    tag.identifier(),
                    stamp.identifier(),
                    value_hi.identifier(),
                    value_lo.identifier(),
                    call_id_contract_addr.identifier(),
                    pointer_hi.identifier(),
                    pointer_lo.identifier(),
                    is_write.identifier(),
                ]
            }
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
                committed_value_lo,
                committed_value_hi,
            } => {
                vec![
                    tag.identifier(),
                    stamp.identifier(),
                    value_hi.identifier(),
                    value_lo.identifier(),
                    call_id_contract_addr.identifier(),
                    key_hi.identifier(),
                    key_lo.identifier(),
                    is_write.identifier(),
                    value_pre_hi.identifier(),
                    value_pre_lo.identifier(),
                    committed_value_lo.identifier(),
                    committed_value_hi.identifier(),
                ]
            }
            LookupEntry::Public {
                tag,
                tx_idx_or_number_diff,
                values,
            } => {
                let mut contents = vec![tag.identifier(), tx_idx_or_number_diff.identifier()];
                contents.extend(values.iter().map(|v| v.identifier()));
                contents
            }
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
            } => {
                vec![
                    src_type.identifier(),
                    src_id.identifier(),
                    src_pointer.identifier(),
                    src_stamp.identifier(),
                    dst_type.identifier(),
                    dst_id.identifier(),
                    dst_pointer.identifier(),
                    dst_stamp.identifier(),
                    cnt.identifier(),
                    len.identifier(),
                    acc.identifier(),
                ]
            }
            LookupEntry::Arithmetic { tag, values } => {
                let mut contents = vec![tag.identifier()];
                contents.extend(values.iter().map(|v| v.identifier()));
                contents
            }
            LookupEntry::ArithmeticTiny { tag, values } => {
                let mut contents = vec![tag.identifier()];
                contents.extend(values.iter().map(|v| v.identifier()));
                contents
            }
            LookupEntry::Bitwise { tag, acc, sum_2 } => {
                let mut contents = vec![tag.identifier()];
                contents.extend(acc.iter().map(|v| v.identifier()));
                contents.push(sum_2.identifier());
                contents
            }
            LookupEntry::MostSignificantByteLen { acc_2, index } => {
                vec![acc_2.identifier(), index.identifier()]
            }
            LookupEntry::ArithmeticShort { tag, values } => {
                let mut contents = vec![tag.identifier()];
                contents.extend(values.iter().map(|v| v.identifier()));
                contents
            }
            LookupEntry::Exp { base, index, power } => {
                let mut contents = vec![];
                for v in [base, index, power] {
                    contents.extend(v.iter().map(|v| v.identifier()))
                }
                contents
            }
            LookupEntry::U10(value) | LookupEntry::U16(value) | LookupEntry::U8(value) => {
                vec![value.identifier()]
            }
            _ => panic!("Not lookup entry!"),
        };
        // 添加Entry枚举自身名称作为去向
        strings.extend(vec![self.as_ref().to_string()]);
        // 使用分隔符将一系列内容合并为一个标识符
        strings.join(SEPARATOR)
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use crate::util::{assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes};
    use crate::witness::{bytecode, exp, Witness};
    use gadgets::is_zero::IsZeroInstruction;
    use halo2_proofs::circuit::{Region, Value};
    use halo2_proofs::plonk::Error;

    impl<F: Field> BytecodeTable<F> {
        /// assign one row of values from witness in a region, used for test
        #[rustfmt::skip]
        fn assign_row(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &bytecode::Row,
        ) -> Result<(), Error> {
            let cnt_is_zero = IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
            assign_advice_or_fixed_with_u256(region, offset, &row.addr.unwrap_or_default(), self.addr)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.bytecode.unwrap_or_default(), self.bytecode)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.pc.unwrap_or_default(), self.pc)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.cnt.unwrap_or_default(), self.cnt)?;
            cnt_is_zero.assign(
                region,
                offset,
                Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                    &row.cnt.unwrap_or_default(),
                ))),
            )?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.bytecode.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }

    impl StateTable {
        /// assign one row of values from witness in a region, used for test
        #[rustfmt::skip]
        fn assign_row<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &state::Row,
        ) -> Result<(), Error> {
            let tag = BinaryNumberChip::construct(self.tag);
            tag.assign(region, offset, &row.tag.unwrap_or_default())?;
            assign_advice_or_fixed_with_u256(region, offset, &row.stamp.unwrap_or_default(), self.stamp)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.call_id_contract_addr.unwrap_or_default(), self.call_id_contract_addr)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.pointer_hi.unwrap_or_default(), self.pointer_hi)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.pointer_lo.unwrap_or_default(), self.pointer_lo)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.is_write.unwrap_or_default(), self.is_write)?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.state.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }
    impl ArithmeticTable {
        /// assign one row of values from witness in a region, used for test
        fn assign_row<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &arithmetic::Row,
        ) -> Result<(), Error> {
            let tag = BinaryNumberChip::construct(self.tag);
            tag.assign(region, offset, &row.tag)?;
            assign_advice_or_fixed_with_u256(
                region,
                offset,
                &row.operand_0_hi,
                self.operands[0][0],
            )?;
            assign_advice_or_fixed_with_u256(
                region,
                offset,
                &row.operand_0_lo,
                self.operands[0][1],
            )?;
            assign_advice_or_fixed_with_u256(
                region,
                offset,
                &row.operand_1_hi,
                self.operands[1][0],
            )?;
            assign_advice_or_fixed_with_u256(
                region,
                offset,
                &row.operand_1_lo,
                self.operands[1][1],
            )?;
            assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.cnt)?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.arithmetic.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }
    impl CopyTable {
        /// assign one row of values from witness in a region, used for test
        fn assign_row<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &copy::Row,
        ) -> Result<(), Error> {
            let src_tag = BinaryNumberChip::construct(self.src_tag);
            src_tag.assign(region, offset, &row.src_type)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.src_id, self.src_id)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.src_pointer, self.src_pointer)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.src_stamp, self.src_stamp)?;
            let dst_tag = BinaryNumberChip::construct(self.dst_tag);
            dst_tag.assign(region, offset, &row.dst_type)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.dst_id, self.dst_id)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.dst_pointer, self.dst_pointer)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.dst_stamp, self.dst_stamp)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.len)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.acc)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.cnt)?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.copy.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }
    impl BitwiseTable {
        /// assign one row of values from witness in a region, used for test
        fn assign_row<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &bitwise::Row,
        ) -> Result<(), Error> {
            let tag = BinaryNumberChip::construct(self.tag);
            tag.assign(region, offset, &row.tag)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.acc_0, self.acc_vec[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.acc_1, self.acc_vec[1])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.acc_2, self.acc_vec[2])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.sum_2, self.sum_2)?;
            assign_advice_or_fixed_with_u256(region, offset, &row.index, self.index)?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.bitwise.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }
    impl ExpTable {
        /// assign one row of values from witness in a region, used for test
        fn assign_row<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &exp::Row,
        ) -> Result<(), Error> {
            assign_advice_or_fixed_with_u256(region, offset, &row.base_hi, self.base[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.base_lo, self.base[1])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.index_hi, self.index[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.index_lo, self.index[1])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.power_hi, self.power[0])?;
            assign_advice_or_fixed_with_u256(region, offset, &row.power_lo, self.power[1])?;
            Ok(())
        }
        /// assign values from witness in a region, used for test
        pub fn assign_with_region<F: Field>(
            &self,
            region: &mut Region<'_, F>,
            witness: &Witness,
        ) -> Result<(), Error> {
            for (offset, row) in witness.exp.iter().enumerate() {
                self.assign_row(region, offset, row)?;
            }
            Ok(())
        }
    }
}
