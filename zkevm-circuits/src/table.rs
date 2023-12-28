use crate::arithmetic_circuit::{LOG_NUM_ARITHMETIC_TAG, NUM_OPERAND};
use crate::constant::LOG_NUM_STATE_TAG;
use crate::witness::fixed;
use crate::witness::{arithmetic, state};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Expression, Fixed, Instance, Selector, VirtualCells,
};
use halo2_proofs::poly::Rotation;

pub const U10_TAG: usize = 256;
const PUBLIC_NUM_VALUES: usize = 4;
pub const SEPARATOR: &str = "-";
pub const ANNOTATE_SEPARATOR: &str = ",";

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
        Self {
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
        let (
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        ) = extract_lookup_expression!(state, entry);
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
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);
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
                vec![(U10_TAG.expr(), table_value_1), (value, table_value_2)]
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
    /// The operands in one row, splitted to 2 (high and low 128-bit)
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

/// Lookup structure. Use this structure to normalize the order of expressions inside lookup.
#[derive(Clone, Debug)]
pub enum LookupEntry<F> {
    // 0-255
    U8(Expression<F>),
    // 1-1024, not 0-1023
    U10(Expression<F>),
    U16(Expression<F>),
    /// Lookup to fixed table
    Fixed {
        /// Tag could be LogicAnd, LogicOr, LogicXor, or PushCnt
        tag: Expression<F>,
        /// Values in logic means operands, in push cnt means (opcode, cnt, is_high)
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
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<LookupEntry<F>>),
    /// Lookup to exp table
    Exp {
        base: [Expression<F>; 2],
        index: [Expression<F>; 2],
        power: [Expression<F>; 2],
    },
    /// Bitwise operation, lookup to Fixed table
    // todo remove this
    BitOp {
        value_1: Expression<F>,
        value_2: Expression<F>,
        result: Expression<F>,
        /// Tag could be LogicAnd, LogicOr or LogicXor
        tag: Expression<F>,
    },

    /// Bitwise lookup operation, lookup to bitwise table
    Bitwise {
        /// Tag could be Nil, And, Or or Xor
        tag: Expression<F>,
        /// Three operands of 128-bit
        acc: [Expression<F>; 3],
        /// The sum of bytes for operand 2, used for BYTE opcode
        sum_2: Expression<F>,
    },
    /// Lookup to Public table
    Public {
        tag: Expression<F>,
        tx_idx_or_number_diff: Expression<F>,
        values: [Expression<F>; PUBLIC_NUM_VALUES],
    },
}

// todo code copied from scroll
impl<F: Field> LookupEntry<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }
}

impl<F: Field> LookupEntry<F> {
    pub fn identifier(&self) -> String {
        let strings = match self {
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
            LookupEntry::BitOp {
                value_1,
                value_2,
                result,
                tag,
            } => {
                vec![
                    value_1.identifier(),
                    value_2.identifier(),
                    result.identifier(),
                    tag.identifier(),
                ]
            }
            LookupEntry::Bitwise { tag, acc, sum_2 } => {
                let mut contents = vec![tag.identifier()];
                contents.extend(acc.iter().map(|v| v.identifier()));
                contents.push(sum_2.identifier());
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
            _ => panic!("Not lookupentry!"),
        };
        strings.join(SEPARATOR)
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes};
    use crate::witness::{bytecode, Witness};
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
            assign_advice_or_fixed(region, offset, &row.addr.unwrap_or_default(), self.addr)?;
            assign_advice_or_fixed(region, offset, &row.bytecode.unwrap_or_default(), self.bytecode)?;
            assign_advice_or_fixed(region, offset, &row.pc.unwrap_or_default(), self.pc)?;
            assign_advice_or_fixed(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
            assign_advice_or_fixed(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
            assign_advice_or_fixed(region, offset, &row.cnt.unwrap_or_default(), self.cnt)?;
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
            assign_advice_or_fixed(region, offset, &row.stamp.unwrap_or_default(), self.stamp)?;
            assign_advice_or_fixed(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
            assign_advice_or_fixed(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
            assign_advice_or_fixed(region, offset, &row.call_id_contract_addr.unwrap_or_default(), self.call_id_contract_addr)?;
            assign_advice_or_fixed(region, offset, &row.pointer_hi.unwrap_or_default(), self.pointer_hi)?;
            assign_advice_or_fixed(region, offset, &row.pointer_lo.unwrap_or_default(), self.pointer_lo)?;
            assign_advice_or_fixed(region, offset, &row.is_write.unwrap_or_default(), self.is_write)?;
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
}
