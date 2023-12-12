use crate::table::{FixedTable, LookupEntry, StateTable};
use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::{fixed, Witness};
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance};
use std::fmt::format;
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
        // And/Or/Xor ==>  0-256行
        let operand_num = 1 << 8;
        let tags = [fixed::Tag::And, fixed::Tag::Or, fixed::Tag::Xor];
        for (i, tag) in tags.iter().enumerate() {
            self.assign_with_tag_value(region, *tag, i * operand_num, operand_num)?;
        }
        let mut acc = 3 * operand_num;

        // assign u8
        for i in 0..1 << 8 {
            region.assign_fixed(
                || "",
                self.tag,
                acc + i,
                || Value::known(F::from(fixed::Tag::And as u64)),
            )?;

            self.assign_value(region, 0, acc + i, "U8", i)?;
        }
        acc = acc + (1 << 8);
        // assign u10
        for i in 0..1 << 10 {
            self.assign_value(region, 1, acc + i, "U10", 256)?;
            self.assign_value(region, 2, acc + i, "U10", i)?;
        }
        acc = acc + (1 << 10);
        //assign u16
        for i in 0..1 << 16 {
            self.assign_value(region, 0, acc + i, "U16", i)?;
        }
        Ok(())
    }

    fn assign_with_tag_value(
        &self,
        region: &mut Region<'_, F>,
        tag: fixed::Tag,
        start: usize,
        row_num: usize,
    ) -> Result<(), Error> {
        let (f, s_tag): (fn(usize) -> usize, &str) = match tag {
            fixed::Tag::And => (|i| i & i, "And"),
            fixed::Tag::Or => (|i| i | i, "Or"),
            fixed::Tag::Xor => (|i| i ^ i, "Xor"),
            _ => (|i| i, "U16"),
        };

        for j in 0..row_num {
            // tag
            region.assign_fixed(
                || format!("assign {} row in fixed table {:?}", start + j, s_tag),
                self.tag,
                start + j,
                || Value::known(F::from(tag as u64)),
            )?;
            // value[0], value[1], value[2],
            self.assign_value(region, 0, start + j, s_tag, j)?;
            self.assign_value(region, 1, start + j, s_tag, j)?;
            self.assign_value(region, 2, start + j, s_tag, f(j))?;
        }
        Ok(())
    }

    fn assign_value(
        &self,
        region: &mut Region<'_, F>,
        index: usize,
        row: usize,
        tag: &str,
        val: usize,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || format!("assign {} row in values{index} fixed column {:?}", row, tag),
            self.values[index],
            row,
            || Value::known(F::from(val as u64)),
        )?;
        Ok(())
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
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (0, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::table::FixedTable;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::Field;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use halo2_proofs::poly::Rotation;

    #[derive(Clone)]
    pub struct FixedTestCircuitConfig<F: Field> {
        pub fixed_circuit: FixedCircuitConfig<F>,
        pub test_advice: Column<Advice>,
    }

    impl<F: Field> FixedTestCircuitConfig<F> {
        fn assign_region(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
            region.assign_advice(
                || "assign u16",
                self.test_advice,
                1,
                || Value::known(F::from(1 << 10)),
            )?;
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
            let test_advice = meta.advice_column();
            meta.lookup_any("test lookup u16", |meta| {
                let entry = LookupEntry::U16(meta.query_advice(test_advice, Rotation::cur()));
                let lookup_vec = fixed_table.get_lookup_vector(meta, entry);
                lookup_vec
                    .into_iter()
                    .map(|(left, right)| (left, right))
                    .collect()
            });

            FixedTestCircuitConfig {
                fixed_circuit: FixedCircuitConfig::new(
                    meta,
                    FixedCircuitConfigArgs { fixed_table },
                ),
                test_advice,
            }
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
    fn test_state_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = FixedTestCircuit::<Fp>::new(witness);
        let instance: Vec<Vec<Fp>> = circuit.0.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_state_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        witness.print_csv();
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }
}
