// use crate::util::{, SubCircuitConfig};

use crate::witness::core::Row;

use crate::execution::ExecutionGadgets;
use crate::table::{BytecodeTable, StackTable};
use crate::util::{self};
use crate::util::{convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::block::{CoreCircuitWitness, SelectorColumn};
use crate::witness::Block;
use crate::witness::{EXECUTION_STATE_NUM, OPERAND_NUM};
use eth_types::Field;

use gadgets::is_zero::IsZeroInstruction;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::circuit::{Region, SimpleFloorPlanner};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CoreCircuitConfig<F> {
    q_enable: Selector,
    // witness column of transaction index
    tx_idx: Column<Advice>,
    // witness column of call id
    call_id: Column<Advice>,
    // witness column of contract address
    code_addr: Column<Advice>,
    // witness column of program counter
    pc: Column<Advice>,
    // witness columns of opcode
    opcode: Column<Advice>,
    // witness column of opcode counter
    cnt: Column<Advice>,
    // wiitness columns of 32 versatile
    vers_0: Column<Advice>,
    vers_1: Column<Advice>,
    vers_2: Column<Advice>,
    vers_3: Column<Advice>,
    vers_4: Column<Advice>,
    vers_5: Column<Advice>,
    vers_6: Column<Advice>,
    vers_7: Column<Advice>,
    vers_8: Column<Advice>,
    vers_9: Column<Advice>,
    vers_10: Column<Advice>,
    vers_11: Column<Advice>,
    vers_12: Column<Advice>,
    vers_13: Column<Advice>,
    vers_14: Column<Advice>,
    vers_15: Column<Advice>,
    vers_16: Column<Advice>,
    vers_17: Column<Advice>,
    vers_18: Column<Advice>,
    vers_19: Column<Advice>,
    vers_20: Column<Advice>,
    vers_21: Column<Advice>,
    vers_22: Column<Advice>,
    vers_23: Column<Advice>,
    vers_24: Column<Advice>,
    vers_25: Column<Advice>,
    vers_26: Column<Advice>,
    vers_27: Column<Advice>,
    vers_28: Column<Advice>,
    vers_29: Column<Advice>,
    vers_30: Column<Advice>,
    vers_31: Column<Advice>,
    // IsZero chip for witness column cnt
    cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// Tables used for lookup
    bytecode_table: BytecodeTable<F>,
}

pub struct CoreCircuitConfigArgs<F> {
    pub q_enable: Selector,
    pub bytecode_table: BytecodeTable<F>,
} // todo change this

impl<F: Field> SubCircuitConfig<F> for CoreCircuitConfig<F> {
    type ConfigArgs = CoreCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            bytecode_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let tx_idx = meta.advice_column();
        let call_id = meta.advice_column();
        let code_addr = meta.advice_column();
        let pc = meta.advice_column();
        let opcode = meta.advice_column();
        let cnt = meta.advice_column();

        let vers_0 = meta.advice_column();
        let vers_1 = meta.advice_column();
        let vers_2 = meta.advice_column();
        let vers_3 = meta.advice_column();
        let vers_4 = meta.advice_column();
        let vers_5 = meta.advice_column();
        let vers_6 = meta.advice_column();
        let vers_7 = meta.advice_column();
        let vers_8 = meta.advice_column();
        let vers_9 = meta.advice_column();
        let vers_10 = meta.advice_column();
        let vers_11 = meta.advice_column();
        let vers_12 = meta.advice_column();
        let vers_13 = meta.advice_column();
        let vers_14 = meta.advice_column();
        let vers_15 = meta.advice_column();
        let vers_16 = meta.advice_column();
        let vers_17 = meta.advice_column();
        let vers_18 = meta.advice_column();
        let vers_19 = meta.advice_column();
        let vers_20 = meta.advice_column();
        let vers_21 = meta.advice_column();
        let vers_22 = meta.advice_column();
        let vers_23 = meta.advice_column();
        let vers_24 = meta.advice_column();
        let vers_25 = meta.advice_column();
        let vers_26 = meta.advice_column();
        let vers_27 = meta.advice_column();
        let vers_28 = meta.advice_column();
        let vers_29 = meta.advice_column();
        let vers_30 = meta.advice_column();
        let vers_31 = meta.advice_column();

        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let config = Self {
            q_enable,
            tx_idx,
            call_id,
            code_addr,
            pc,
            opcode,
            cnt,
            vers_0,
            vers_1,
            vers_2,
            vers_3,
            vers_4,
            vers_5,
            vers_6,
            vers_7,
            vers_8,
            vers_9,
            vers_10,
            vers_11,
            vers_12,
            vers_13,
            vers_14,
            vers_15,
            vers_16,
            vers_17,
            vers_18,
            vers_19,
            vers_20,
            vers_21,
            vers_22,
            vers_23,
            vers_24,
            vers_25,
            vers_26,
            vers_27,
            vers_28,
            vers_29,
            vers_30,
            vers_31,
            cnt_is_zero,
            bytecode_table,
        };

        meta.create_gate("Core Circuit counter", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_cur = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            vec![q_enable * (1.expr() - cnt_is_zero) * (cnt_prev - cnt_cur - 1.expr())]
        });

        meta.create_gate("Program, Counter", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let pc_cur = meta.query_advice(config.pc, Rotation::cur());
            let pc_prev = meta.query_advice(config.pc, Rotation::prev());
            vec![q_enable * (1.expr() - cnt_is_zero) * (pc_prev - pc_cur)]
        });

        // tx_id, call_id, code_addr constraints?
        config
    }
}

#[derive(Clone, Default, Debug)]
pub struct CoreCircuit<F: Field> {
    witness: Vec<Row>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for CoreCircuit<F> {
    type Config = CoreCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.complex_selector();
        let bytecode_table = BytecodeTable::construct(meta, q_enable);
        Self::Config::new(
            meta,
            CoreCircuitConfigArgs {
                q_enable,
                bytecode_table,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cnt_is_zero = IsZeroWithRotationChip::construct(config.cnt_is_zero.clone());

        layouter.assign_region(
            || "core",
            |mut region| {
                // annotate columns todo
                region.name_column(|| "cnt", config.cnt);
                for (offset, row) in self.witness.iter().enumerate() {
                    region.assign_advice(
                        || "cnt",
                        config.cnt,
                        offset,
                        || Value::known(F::from_u128(row.cnt.as_u128())),
                    )?;
                    region.assign_advice(
                        || "tx_idx",
                        config.tx_idx,
                        offset,
                        || Value::known(F::from_u128(row.tx_idx.as_u128())),
                    )?;
                    region.assign_advice(
                        || "call_id",
                        config.call_id,
                        offset,
                        || Value::known(F::from_u128(row.call_id.as_u128())),
                    )?;
                    region.assign_advice(
                        || "code_addr",
                        config.code_addr,
                        offset,
                        || {
                            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                                &row.code_addr,
                            )))
                        },
                    )?;
                    region.assign_advice(
                        || "pc",
                        config.pc,
                        offset,
                        || Value::known(F::from_u128(row.pc.as_u128())),
                    )?;
                    region.assign_advice(
                        || "opcode",
                        config.opcode,
                        offset,
                        || Value::known(F::from_u128(row.opcode.as_u8() as u128)),
                    )?;
                    region.assign_advice(
                        || "vers_0",
                        config.vers_0,
                        offset,
                        || Value::known(F::from_u128(row.vers_0.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_1",
                        config.vers_1,
                        offset,
                        || Value::known(F::from_u128(row.vers_1.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_2",
                        config.vers_2,
                        offset,
                        || Value::known(F::from_u128(row.vers_2.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_3",
                        config.vers_3,
                        offset,
                        || Value::known(F::from_u128(row.vers_3.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_4",
                        config.vers_4,
                        offset,
                        || Value::known(F::from_u128(row.vers_4.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_5",
                        config.vers_5,
                        offset,
                        || Value::known(F::from_u128(row.vers_5.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_6",
                        config.vers_6,
                        offset,
                        || Value::known(F::from_u128(row.vers_2.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_7",
                        config.vers_7,
                        offset,
                        || Value::known(F::from_u128(row.vers_3.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_8",
                        config.vers_8,
                        offset,
                        || Value::known(F::from_u128(row.vers_8.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_9",
                        config.vers_9,
                        offset,
                        || Value::known(F::from_u128(row.vers_9.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_10",
                        config.vers_10,
                        offset,
                        || Value::known(F::from_u128(row.vers_10.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_11",
                        config.vers_11,
                        offset,
                        || Value::known(F::from_u128(row.vers_11.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_12",
                        config.vers_12,
                        offset,
                        || Value::known(F::from_u128(row.vers_12.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_13",
                        config.vers_13,
                        offset,
                        || Value::known(F::from_u128(row.vers_13.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_14",
                        config.vers_14,
                        offset,
                        || Value::known(F::from_u128(row.vers_14.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_15",
                        config.vers_15,
                        offset,
                        || Value::known(F::from_u128(row.vers_15.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_16",
                        config.vers_16,
                        offset,
                        || Value::known(F::from_u128(row.vers_16.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_17",
                        config.vers_17,
                        offset,
                        || Value::known(F::from_u128(row.vers_17.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_18",
                        config.vers_18,
                        offset,
                        || Value::known(F::from_u128(row.vers_18.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_19",
                        config.vers_19,
                        offset,
                        || Value::known(F::from_u128(row.vers_19.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_20",
                        config.vers_20,
                        offset,
                        || Value::known(F::from_u128(row.vers_20.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_21",
                        config.vers_21,
                        offset,
                        || Value::known(F::from_u128(row.vers_21.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_22",
                        config.vers_22,
                        offset,
                        || Value::known(F::from_u128(row.vers_22.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_23",
                        config.vers_23,
                        offset,
                        || Value::known(F::from_u128(row.vers_23.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_24",
                        config.vers_24,
                        offset,
                        || Value::known(F::from_u128(row.vers_24.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_25",
                        config.vers_25,
                        offset,
                        || Value::known(F::from_u128(row.vers_25.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_26",
                        config.vers_26,
                        offset,
                        || Value::known(F::from_u128(row.vers_26.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_27",
                        config.vers_27,
                        offset,
                        || Value::known(F::from_u128(row.vers_27.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_28",
                        config.vers_28,
                        offset,
                        || Value::known(F::from_u128(row.vers_28.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_29",
                        config.vers_29,
                        offset,
                        || Value::known(F::from_u128(row.vers_29.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_30",
                        config.vers_30,
                        offset,
                        || Value::known(F::from_u128(row.vers_30.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_31",
                        config.vers_31,
                        offset,
                        || Value::known(F::from_u128(row.vers_31.unwrap_or_default().as_u128())),
                    )?;

                    // do not enable first and last padding row
                    // todo what should be it
                    if offset > 2 && offset < (&self.witness).len() - 1 {
                        config.q_enable.enable(&mut region, offset)?;
                    }
                    cnt_is_zero.assign(
                        &mut region,
                        offset,
                        Value::known(F::from_u128(row.cnt.as_u128())),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> CoreCircuit<F> {
    pub fn new(witness: Vec<Row>) -> Self {
        Self {
            witness,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core_circuit::CoreCircuit;

    use crate::witness::core::Row;
    use eth_types::evm_types::OpcodeId;

    use eth_types::U256;
    use halo2_proofs::halo2curves::ff::FromUniformBytes;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr as Fp};

    fn test_simple_core_circuit(row_0: Row, row_1: Row, row_2: Row) {
        let k = 8;
        let padding = Row::default();
        let rows = vec![
            padding.clone(),
            padding.clone(),
            row_0,
            row_1,
            row_2,
            padding,
        ];
        let circuit = CoreCircuit::<Fp>::new(rows);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied_par();
    }

    #[test]

    fn test_core_circuit_with_three_rows() {
        let row_0: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 2.into(),
            vers_0: Some(U256::from(0)),
            ..Default::default()
        };

        let row_1: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 1.into(),
            ..Default::default()
        };

        let row_2: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 0.into(),
            ..Default::default()
        };

        test_simple_core_circuit(row_0, row_1, row_2);
    }
    #[test]
    fn test_convert() {
        let num: [u8; 64] = [0u8; 64];
        let mut number_255 = num.clone();
        number_255[0] = 255;
        assert_eq!(Fp::from_uniform_bytes(&number_255), Fp::from(255));

        let mut number_256 = num.clone();
        number_256[1] = 1;
        assert_eq!(Fp::from_uniform_bytes(&number_256), Fp::from(256));
    }
}
