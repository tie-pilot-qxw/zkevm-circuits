use crate::witness::arithmetic::{self, Row, Tag};
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance};

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
pub struct BytecodeTable {
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
}

impl BytecodeTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            addr: meta.advice_column(),
            pc: meta.advice_column(),
            bytecode: meta.advice_column(),
            value_hi: meta.advice_column(),
            value_lo: meta.advice_column(),
        }
    }

    pub fn assign() {
        todo!()
    }
}

/// The table used to do range check lookup
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

    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // for (column, exponent) in [(self.u8, 8), (self.u10, 10), (self.u16, 16)] {
        // to reduce running time, we only load u8 for now
        for (column, exponent) in [(self.u8, 8)] {
            layouter.assign_region(
                || format!("assign u{} fixed column", exponent),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {} in u{} fixed column", i, exponent),
                            column,
                            i,
                            || Value::known(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
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
