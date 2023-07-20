use crate::table::BytecodeTable;
use crate::util::{Expr, SubCircuit, SubCircuitConfig};
use crate::witness::block::{BytecodeWitness, SelectorColumn};
use crate::witness::{Block, Witness};
use eth_types::evm_types::OpcodeId::PUSH1;
use eth_types::{Field, U256};
use halo2_proofs::circuit::{Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use std::iter::{once, zip};

use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct BytecodeCircuitConfig<F> {
    q_enable: Selector,
    /// the contract address of the bytecodes. public input
    instance_addr: Column<Instance>,
    /// bytecode, operation code or pushed value. public input
    instance_bytecode: Column<Instance>,
    /// the contract address of the bytecodes (need to copy from public input)
    addr: Column<Advice>,
    /// the index that program counter points to
    pc: Column<Advice>,
    /// bytecode, operation code or pushed value (need to copy from public input)
    bytecode: Column<Advice>,
    /// pushed value, high 128 bits
    value_hi: Column<Advice>,
    /// pushed value, low 128 bits
    value_lo: Column<Advice>,
    /// accumulated value, high 128 bits. accumulation will go X times for PUSHX
    acc_hi: Column<Advice>,
    /// accumulated value, low 128 bits. accumulation will go X times for PUSHX
    acc_lo: Column<Advice>,
    /// count for accumulation, accumulation will go X times for PUSHX
    cnt: Column<Advice>,
    /// whether count is equal or larger than 16
    is_high: Column<Advice>,
    /// for chip to determine whether cnt is 0
    cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// for chip to determine whether cnt is 15
    cnt_is_15: IsZeroConfig<F>,
    /// for chip to check if addr is changed from previous row
    addr_unchange: IsZeroConfig<F>,
    _marker: PhantomData<F>,
}

pub struct BytecodeCircuitConfigArgs {
    pub(crate) bytecode_table: BytecodeTable,
}

impl<F: Field> SubCircuitConfig<F> for BytecodeCircuitConfig<F> {
    type ConfigArgs = BytecodeCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { bytecode_table }: Self::ConfigArgs,
    ) -> Self {
        let BytecodeTable {
            addr,
            pc,
            bytecode,
            value_hi,
            value_lo,
        } = bytecode_table;
        let q_enable = meta.complex_selector();
        let acc_hi = meta.advice_column();
        let acc_lo = meta.advice_column();
        let cnt = meta.advice_column();
        let is_high = meta.advice_column();
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);
        let _cnt_minus_15_inv = meta.advice_column();
        let cnt_is_15 = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt = meta.query_advice(cnt, Rotation::cur());
                cnt - 15.expr()
            },
            _cnt_minus_15_inv,
        );
        let _addr_diff = meta.advice_column();
        let instance_addr = meta.instance_column();
        let instance_bytecode = meta.instance_column();
        let addr_unchange = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let addr_cur = meta.query_advice(addr, Rotation::cur());
                let addr_prev = meta.query_advice(addr, Rotation::prev());
                addr_cur - addr_prev
            },
            _addr_diff,
        );
        // we need to copy (equality) from public input to advice column
        meta.enable_equality(instance_addr);
        meta.enable_equality(addr);
        meta.enable_equality(instance_bytecode);
        meta.enable_equality(bytecode);
        let config = Self {
            q_enable,
            instance_addr,
            instance_bytecode,
            addr,
            pc,
            bytecode,
            value_hi,
            value_lo,
            acc_hi,
            acc_lo,
            cnt,
            is_high,
            cnt_is_zero,
            cnt_is_15,
            addr_unchange,
            _marker: PhantomData,
        };
        // add all gate constraints here
        meta.create_gate("BYTECODE_cnt_decrease", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            let cnt_cur = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            vec![q_enable * (1.expr() - cnt_is_zero_prev) * (cnt_prev - cnt_cur - 1.expr())]
        });
        meta.create_gate("BYTECODE_pc_increase_or_zero", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let addr_unchange = config.addr_unchange.expr();
            let pc_cur = meta.query_advice(config.pc, Rotation::cur());
            let pc_prev = meta.query_advice(config.pc, Rotation::prev());
            vec![
                q_enable
                    * ((1.expr() - addr_unchange.clone()) * pc_cur.clone()
                        + addr_unchange * (pc_cur - pc_prev - 1.expr())),
            ]
        });
        // todo many more gates
        // add all lookup constraints here todo
        config
    }
}

impl<F: Field> BytecodeCircuitConfig<F> {
    /// assign values from witness in a region, except for values copied from instance
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_padding_row: usize,
    ) -> Result<(), Error> {
        let cnt_is_zero = IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let cnt_is_15 = IsZeroChip::construct(self.cnt_is_15.clone());
        let addr_unchange = IsZeroChip::construct(self.addr_unchange.clone());
        // assign padding rows
        for offset in 0..num_padding_row {
            region.assign_advice(|| "pc", self.pc, offset, || Value::known(F::ZERO))?;
            region.assign_advice(
                || "value_hi",
                self.value_hi,
                offset,
                || Value::known(F::ZERO),
            )?;
            region.assign_advice(
                || "value_lo",
                self.value_lo,
                offset,
                || Value::known(F::ZERO),
            )?;
            region.assign_advice(|| "acc_hi", self.acc_hi, offset, || Value::known(F::ZERO))?;
            region.assign_advice(|| "acc_lo", self.acc_lo, offset, || Value::known(F::ZERO))?;
            region.assign_advice(|| "cnt", self.cnt, offset, || Value::known(F::ZERO))?;
            region.assign_advice(|| "is_high", self.is_high, offset, || Value::known(F::ZERO))?;
            cnt_is_zero.assign(region, offset, Value::known(F::ZERO))?;
            cnt_is_15.assign(region, offset, Value::known(F::ZERO))?;
            addr_unchange.assign(region, offset, Value::known(F::ZERO))?;
        }
        // assign values from witness
        for (offset, row) in witness.bytecode.iter().enumerate() {
            region.assign_advice(
                || "pc",
                self.pc,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.pc.as_u128())),
            )?;
            region.assign_advice(
                || "value_hi",
                self.value_hi,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.value_hi.unwrap_or_default().as_u128())),
            )?;
            region.assign_advice(
                || "value_lo",
                self.value_lo,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.value_lo.unwrap_or_default().as_u128())),
            )?;
            region.assign_advice(
                || "acc_hi",
                self.acc_hi,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.acc_hi.unwrap_or_default().as_u128())),
            )?;
            region.assign_advice(
                || "acc_lo",
                self.acc_lo,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.acc_lo.unwrap_or_default().as_u128())),
            )?;
            region.assign_advice(
                || "cnt",
                self.cnt,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.cnt.as_u128())),
            )?;
            region.assign_advice(
                || "is_high",
                self.is_high,
                num_padding_row + offset,
                || Value::known(F::from_u128(row.is_high.as_u128())),
            )?;
            cnt_is_zero.assign(
                region,
                num_padding_row + offset,
                Value::known(F::from_u128(row.cnt.as_u128())),
            )?;
            cnt_is_15.assign(
                region,
                num_padding_row + offset,
                Value::known(F::from_u128(row.cnt.as_u128()) - F::from(15)),
            )?;
        }
        for (offset, (addr_cur, addr_prev)) in zip(
            witness.bytecode.iter().map(|row| row.addr),
            once(U256::zero()).chain(witness.bytecode.iter().map(|row| row.addr)),
        )
        .enumerate()
        {
            addr_unchange.assign(
                region,
                num_padding_row + offset,
                Value::known(F::from_u128(addr_cur.as_u128()) - F::from_u128(addr_prev.as_u128())),
            )?;
        }
        Ok(())
    }

    /// assign values copied from instance
    pub fn assign_from_instance_with_region(
        &self,
        region: &mut Region<'_, F>,
        num_padding_row: usize,
        max_codesize: usize,
    ) -> Result<(), Error> {
        // assign padding rows
        for offset in 0..num_padding_row {
            region.assign_advice(|| "addr", self.addr, offset, || Value::known(F::ZERO))?;
            region.assign_advice(
                || "bytecode",
                self.bytecode,
                offset,
                || Value::known(F::ZERO),
            )?;
        }
        // use permutation to copy bytecode from instance to advice
        for offset in 0..max_codesize {
            // not padding, we use permutation constraint to copy addr and bytecode from instance
            // although this is inside synthesize(), this add constraints to the system
            region.assign_advice_from_instance(
                || "addr",
                self.instance_addr,
                offset,
                self.addr,
                num_padding_row + offset,
            )?;
            region.assign_advice_from_instance(
                || "bytecode",
                self.instance_bytecode,
                offset,
                self.bytecode,
                num_padding_row + offset,
            )?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "BYTECODE_addr", self.addr);
        region.name_column(|| "BYTECODE_pc", self.pc);
        region.name_column(|| "BYTECODE_bytecode", self.bytecode);
        region.name_column(|| "BYTECODE_value_hi", self.value_hi);
        region.name_column(|| "BYTECODE_value_lo", self.value_lo);
        region.name_column(|| "BYTECODE_acc_hi", self.acc_hi);
        region.name_column(|| "BYTECODE_acc_lo", self.acc_lo);
        region.name_column(|| "BYTECODE_cnt", self.cnt);
        region.name_column(|| "BYTECODE_is_high", self.is_high);
        self.cnt_is_zero
            .annotate_columns_in_region(region, "BYTECODE_cnt_is_zero");
        self.cnt_is_15
            .annotate_columns_in_region(region, "BYTECODE_cnt_is_15");
        self.addr_unchange
            .annotate_columns_in_region(region, "BYTECODE_addr_unchange");
    }
}

#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field> {
    block: Block<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for BytecodeCircuit<F> {
    type Config = BytecodeCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        BytecodeCircuit {
            block: block.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(|| "bytecode circuit", |mut region| Ok(()))
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::witness::bytecode::Row;
    use crate::witness::Witness;
    use eth_types::evm_types::OpcodeId;
    use eth_types::Field;
    use eth_types::U256;
    use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr as Fp};
    use std::marker::PhantomData;

    /// A standalone circuit for testing
    #[derive(Clone, Default, Debug)]
    pub struct BytecodeTestCircuit<F: Field, const MAX_CODESIZE: usize> {
        witness: Witness,
        num_padding_row: usize,
        _marker: PhantomData<F>,
    }

    impl<F: Field, const MAX_CODESIZE: usize> Circuit<F> for BytecodeTestCircuit<F, MAX_CODESIZE> {
        type Config = BytecodeCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let bytecode_table = BytecodeTable::construct(meta);
            Self::Config::new(meta, BytecodeCircuitConfigArgs { bytecode_table })
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // let cnt_is_zero = IsZeroWithRotationChip::construct(config.cnt_is_zero.clone());
            // let cnt_is_15 = IsZeroChip::construct(config.cnt_is_15.clone());
            // let addr_unchange = IsZeroChip::construct(config.addr_unchange.clone());
            layouter.assign_region(
                || "bytecode for test",
                |mut region| {
                    config.annotate_circuit_in_region(&mut region);
                    config.assign_with_region(&mut region, &self.witness, self.num_padding_row)?;
                    config.assign_from_instance_with_region(
                        &mut region,
                        self.num_padding_row,
                        MAX_CODESIZE,
                    )?;
                    // todo should do a constant number of enable()
                    for offset in 0..self.witness.bytecode.len() {
                        if offset >= self.num_padding_row {
                            config.q_enable.enable(&mut region, offset)?;
                        }
                    }

                    Ok(())
                },
            )
        }
    }

    impl<F: Field, const MAX_CODESIZE: usize> BytecodeTestCircuit<F, MAX_CODESIZE> {
        pub fn new(witness: Witness, first_rows_to_pad: usize) -> Self {
            Self {
                witness,
                num_padding_row: first_rows_to_pad,
                _marker: PhantomData,
            }
        }
    }

    #[test]
    fn one_contract() {
        let num_padding: usize = 1;
        let row1 = Row {
            addr: "0x25556666".into(),
            bytecode: OpcodeId::PUSH1.as_u8().into(),
            cnt: 1.into(),
            ..Default::default()
        };
        let row2 = Row {
            addr: "0x25556666".into(),
            pc: 1.into(),
            ..Default::default()
        };
        let row3 = Row {
            addr: "0x25556666".into(),
            pc: 2.into(),
            bytecode: OpcodeId::PUSH1.as_u8().into(),
            cnt: 1.into(),
            ..Default::default()
        };
        let row4 = Row {
            addr: "0x25556666".into(),
            pc: 3.into(),
            ..Default::default()
        };
        let row5 = Row {
            addr: "0x25556666".into(),
            pc: 4.into(),
            bytecode: OpcodeId::STOP.as_u8().into(),
            ..Default::default()
        };
        let row6 = Row {
            addr: "0x66668888".into(),
            pc: 1.into(),
            bytecode: OpcodeId::STOP.as_u8().into(),
            ..Default::default()
        };
        let mut witness = Witness {
            bytecode: vec![row1, row2, row3, row4, row5, row6],
            ..Default::default()
        };
        let mut instance = {
            let vec_addr: Vec<Fp> = witness
                .bytecode
                .iter()
                .map(|row| Fp::from_u128(row.addr.as_u128()))
                .collect();
            // debug what if we pop one from it?
            let vec_bytecode: Vec<Fp> = witness
                .bytecode
                .iter()
                .map(|row| Fp::from_u128(row.bytecode.as_u128()))
                .collect();
            vec![vec_addr, vec_bytecode]
        };
        // insert padding rows (rows with all 0)
        // for _ in 0..num_padding {
        //     witness.bytecode.insert(0, Default::default());
        // }
        // println!("instance\n{:?}\n", instance);

        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        for row in &witness.bytecode {
            wtr.serialize(&row).unwrap();
        }
        wtr.flush().unwrap();

        let k = 8;
        const MAX_CODESIZE: usize = 200;
        let circuit = BytecodeTestCircuit::<Fp, MAX_CODESIZE>::new(witness.clone(), num_padding);
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover.assert_satisfied_par();
    }
}
