use crate::witness::arithmetic;
use eth_types::Field;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
};

/// The table shared between Core Circuit and Stack Circuit
#[derive(Clone, Copy, Debug)]
pub struct StackTable {
    pub stack_stamp: Column<Advice>,
    pub value: Column<Advice>,
    pub is_write: Column<Advice>,
    pub address: Column<Advice>,
}

impl StackTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            stack_stamp: meta.advice_column(),
            value: meta.advice_column(),
            is_write: meta.advice_column(),
            address: meta.advice_column(),
        }
    }

    pub fn assign<F: Field>(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _the_values: Value<F>,
    ) -> Result<(), Error> {
        todo!();
        panic!("see region.assign_advice")
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
            cnt_is_zero,
        }
    }
}
// TODO re-write
#[derive(Clone, Copy, Debug)]
pub struct FixedTable {
    pub u8: Column<Fixed>,
    pub u10: Column<Fixed>,
    pub u16: Column<Fixed>,
}

impl FixedTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let table = Self {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
        };
        meta.annotate_lookup_any_column(table.u8, || "LOOKUP_u8");
        meta.annotate_lookup_any_column(table.u10, || "LOOKUP_u10");
        meta.annotate_lookup_any_column(table.u16, || "LOOKUP_u16");
        table
    }
}

/// Lookup structure. Use this structure to normalize the order of expressions inside lookup.
#[derive(Clone, Debug)]
pub enum Lookup<F> {
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
    /// Lookup to bytecode table, which contains all used creation code and
    /// contract code.
    Bytecode {
        /// Address of the contract
        addr: Expression<F>,
        /// Program counter or the index of bytecodes
        pc: Expression<F>,
        /// The opcode or bytecode
        opcode: Expression<F>,
        /// Whether this pc points to a code or a pushed value
        is_code: Expression<F>,
        /// Pushed value, high 128 bits (0 or non-push opcodes)
        value_hi: Expression<F>,
        /// Pushed value, low 128 bits (0 or non-push opcodes)
        value_lo: Expression<F>,
    },
    /// Lookup to copy table.
    CopyTable {
        // /// Whether the row is the first row of the copy event.
        // is_first: Expression<F>,
        // /// The source ID for the copy event.
        // src_id: Expression<F>,
        // /// The source tag for the copy event.
        // src_tag: Expression<F>,
        // /// The destination ID for the copy event.
        // dst_id: Expression<F>,
        // /// The destination tag for the copy event.
        // dst_tag: Expression<F>,
        // /// The source address where bytes are copied from.
        // src_addr: Expression<F>,
        // /// The source address where all source-side bytes have been copied.
        // /// This does not necessarily mean there no more bytes to be copied, but
        // /// any bytes following this address will indicating padding.
        // src_addr_end: Expression<F>,
        // /// The destination address at which bytes are copied.
        // dst_addr: Expression<F>,
        // /// The number of bytes to be copied in this copy event.
        // length: Expression<F>,
        // /// The RLC accumulator value, which is used for SHA3 opcode.
        // rlc_acc: Expression<F>,
        // /// The RW counter at the start of the copy event.
        // rw_counter: Expression<F>,
        // /// The RW counter that is incremented by the time all bytes have been
        // /// copied specific to this copy event.
        // rwc_inc: Expression<F>,
    },
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<Lookup<F>>),
}

// todo code copied from scroll
impl<F: Field> Lookup<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ArithmeticTable {
    // the tag to represent arithmetic opcdes
    tag: arithmetic::Tag,
    operand0_hi: Column<Advice>,
    operand0_lo: Column<Advice>,
    operand1_hi: Column<Advice>,
    operand1_lo: Column<Advice>,
    operand2_hi: Column<Advice>,
    operand2_lo: Column<Advice>,
    operand3_hi: Column<Advice>,
    operand3_lo: Column<Advice>,
}
