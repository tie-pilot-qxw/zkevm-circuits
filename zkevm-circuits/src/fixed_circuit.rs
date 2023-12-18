use crate::table::{FixedTable, U10_TAG};
use crate::util::{assign_advice_or_fixed, SubCircuit, SubCircuitConfig};
use crate::witness::{fixed, Witness};
use eth_types::{Field, U256};
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Fixed};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct FixedCircuitConfig<F> {
    tag: Column<Fixed>,
    values: [Column<Fixed>; 3],
    _marker: PhantomData<F>,
}

pub struct FixedCircuitConfigArgs {
    pub fixed_table: FixedTable,
}

impl<F: Field> SubCircuitConfig<F> for FixedCircuitConfig<F> {
    type ConfigArgs = FixedCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { fixed_table }: Self::ConfigArgs,
    ) -> Self {
        let FixedTable { tag, values } = fixed_table;
        Self {
            tag,
            values,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> FixedCircuitConfig<F> {
    fn assgin_with_region(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        #[rustfmt::skip]
        let assign_row = |row: &fixed::Row, index| -> Result<(), Error> {
            assign_advice_or_fixed(region, index, &U256::from(row.tag as u32), self.tag)?;
            assign_advice_or_fixed(region, index, &row.value_0.unwrap_or_default(), self.values[0])?;
            assign_advice_or_fixed(region, index, &row.value_1.unwrap_or_default(), self.values[1])?;
            assign_advice_or_fixed(region, index, &row.value_2.unwrap_or_default(), self.values[2])?;
            Ok(())
        };
        Self::assign(assign_row)?;
        Ok(())
    }

    fn assign(
        mut assign_row: impl FnMut(&fixed::Row, usize) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        // And/Or/Xor ==>  0-256行
        let operand_num = 1 << 8;
        let mut vec = vec![];
        for tag in [fixed::Tag::And, fixed::Tag::Or, fixed::Tag::Xor].iter() {
            vec.append(&mut Self::assign_with_tag_value(*tag, operand_num));
        }
        // assign u10
        for i in 0..1 << 10 {
            vec.push(fixed::Row {
                value_1: Some(U256::from(U10_TAG)),
                value_2: Some(U256::from(i)),
                ..Default::default()
            });
        }
        //assign u16
        for i in 0..1 << 16 {
            vec.push(fixed::Row {
                value_0: Some(U256::from(i)),
                ..Default::default()
            });
        }

        let num = vec.len();
        for (i, row) in vec.iter().enumerate() {
            assign_row(row, i)?;
        }
        Ok(num)
    }

    fn assign_with_tag_value(tag: fixed::Tag, operand_num: usize) -> Vec<fixed::Row> {
        let f = match tag {
            fixed::Tag::And => |i, j| i & j,
            fixed::Tag::Or => |i, j| i | j,
            fixed::Tag::Xor => |i, j| i ^ j,
            _ => panic!("not known tag {:?}", tag),
        };

        let mut vec = vec![];
        for i in 0..operand_num {
            for j in 0..operand_num {
                let row = fixed::Row {
                    tag: tag,
                    value_0: Some(U256::from(i)),
                    value_1: Some(U256::from(j)),
                    value_2: Some(U256::from(f(i, j))),
                };
                vec.push(row);
            }
        }
        vec
    }
}

#[derive(Clone, Default, Debug)]
pub struct FixedCircuit<F: Field> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for FixedCircuit<F> {
    type Config = FixedCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        FixedCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed circuit",
            |mut region| config.assgin_with_region(&mut region),
        )?;
        Ok(())
    }

    fn unusable_rows() -> (usize, usize) {
        (0, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        let f = |row: &_, index| -> Result<(), Error> { Ok(()) };
        FixedCircuitConfig::<F>::assign(f).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::table::{FixedTable, LookupEntry};
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::{bytecode, Field};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Advice, Circuit, ConstraintSystem, Error};
    use halo2_proofs::poly::Rotation;

    #[derive(Clone)]
    pub struct FixedTestCircuitConfig<F: Field> {
        pub fixed_circuit: FixedCircuitConfig<F>,
        pub test_u16: Column<Advice>,
        pub test_u10: Column<Advice>,
        pub test_u8: Column<Advice>,
    }

    impl<F: Field> FixedTestCircuitConfig<F> {
        fn assign_region(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
            assign_advice_or_fixed(region, 1, &U256::from(1 << 16 - 1), self.test_u16)?;
            assign_advice_or_fixed(region, 10, &U256::from(1 << 13), self.test_u16)?;
            assign_advice_or_fixed(region, 1, &U256::from(1 << 10 - 1), self.test_u10)?;
            assign_advice_or_fixed(region, 9, &U256::from(1 << 9), self.test_u10)?;
            assign_advice_or_fixed(region, 1, &U256::from(1 << 8 - 1), self.test_u8)?;
            assign_advice_or_fixed(region, 3, &U256::from(1 << 5), self.test_u8)?;
            Ok(())
        }
    }

    #[derive(Clone, Default, Debug)]
    pub struct FixedTestCircuit<F: Field>(FixedCircuit<F>);

    impl<F: Field> Circuit<F> for FixedTestCircuit<F> {
        type Config = FixedTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let fixed_table = FixedTable::construct(meta);
            let config = FixedTestCircuitConfig {
                fixed_circuit: FixedCircuitConfig::new(
                    meta,
                    FixedCircuitConfigArgs { fixed_table },
                ),
                test_u16: meta.advice_column(),
                test_u10: meta.advice_column(),
                test_u8: meta.advice_column(),
            };
            meta.lookup_any("test lookup u16", |meta| {
                let entry = LookupEntry::U16(meta.query_advice(config.test_u16, Rotation::cur()));
                fixed_table.get_lookup_vector(meta, entry)
            });
            meta.lookup_any("test lookup u10", |meta| {
                let entry = LookupEntry::U10(meta.query_advice(config.test_u10, Rotation::cur()));
                fixed_table.get_lookup_vector(meta, entry)
            });
            meta.lookup_any("test lookup u8", |meta| {
                let entry = LookupEntry::U8(meta.query_advice(config.test_u8, Rotation::cur()));
                fixed_table.get_lookup_vector(meta, entry)
            });
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.0
                .synthesize_sub(&config.fixed_circuit, &mut layouter)?;
            layouter.assign_region(
                || "assign test value",
                |mut region| config.assign_region(&mut region),
            )
        }
    }

    impl<F: Field> FixedTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self(FixedCircuit::new_from_witness(&witness))
        }
    }
    fn test_fixed_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(FixedCircuit::<Fp>::num_rows(&witness));
        let circuit = FixedTestCircuit::<Fp>::new(witness);
        let instance: Vec<Vec<Fp>> = circuit.0.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_fixed_parser() {
        let bytecode = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            ADD
        };
        let trace = trace_parser::trace_program(bytecode.to_vec().as_slice());
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            bytecode.to_vec().as_slice(),
            &[],
            false,
            Default::default(),
        ));
        witness.print_csv();
        let prover = test_fixed_circuit(witness);
        prover.assert_satisfied_par();
    }
}
