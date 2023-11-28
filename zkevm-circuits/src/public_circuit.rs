use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::state::{Row, Tag};
use crate::witness::Witness;
use eth_types::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Instance};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_VALUES: usize = 4;

#[derive(Clone, Debug)]
pub struct PublicCircuitConfig {
    tag: Column<Instance>,
    tx_idx_or_number_diff: Column<Instance>,
    values: [Column<Instance>; NUM_VALUES],
}

impl<F: Field> SubCircuitConfig<F> for PublicCircuitConfig {
    type ConfigArgs = ();

    fn new(meta: &mut ConstraintSystem<F>, _: Self::ConfigArgs) -> Self {
        Self {
            tag: meta.instance_column(),
            tx_idx_or_number_diff: meta.instance_column(),
            values: std::array::from_fn(|_| meta.instance_column()),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct PublicCircuit<F: Field> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for PublicCircuit<F> {
    type Config = PublicCircuitConfig;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        PublicCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut tag = vec![];
        let mut tx_idx_or_number_diff = vec![];
        let mut values: [Vec<F>; NUM_VALUES] = std::array::from_fn(|_| vec![]);
        for row in &self.witness.public {
            tag.push(F::from_u128(row.tag as u128));
            tx_idx_or_number_diff.push(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row.tx_idx_or_number_diff.unwrap_or_default(),
            )));
            let array: [_; NUM_VALUES] = [row.value_0, row.value_1, row.value_2, row.value_3];
            for i in 0..NUM_VALUES {
                values[i].push(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                    &array[i].unwrap_or_default(),
                )));
            }
        }
        let mut res = vec![tag, tx_idx_or_number_diff];
        res.extend(values);
        res
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        mut _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn unusable_rows() -> (usize, usize) {
        (0, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        // bytecode witness length plus must-have padding in the end
        Self::unusable_rows().1 + witness.public.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone, Default, Debug)]
    pub struct PublicTestCircuit<F: Field>(PublicCircuit<F>);
    #[derive(Clone)]
    pub struct PublicTestCircuitConfig {
        pub public_circuit_config: PublicCircuitConfig,
        pub tag: Column<Advice>,
        pub tx_idx_or_number_diff: Column<Advice>,
        pub values: [Column<Advice>; NUM_VALUES],
    }

    impl<F: Field> Circuit<F> for PublicTestCircuit<F> {
        type Config = PublicTestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let public_circuit_config = PublicCircuitConfig::new(meta, ());
            let config = PublicTestCircuitConfig {
                public_circuit_config,
                tag: meta.advice_column(),
                tx_idx_or_number_diff: meta.advice_column(),
                values: std::array::from_fn(|_| meta.advice_column()),
            };
            meta.lookup_any("test lookup", |meta| {
                let mut v = vec![
                    (
                        meta.query_advice(config.tag, Rotation::cur()),
                        meta.query_instance(config.public_circuit_config.tag, Rotation::cur()),
                    ),
                    (
                        meta.query_advice(config.tx_idx_or_number_diff, Rotation::cur()),
                        meta.query_instance(
                            config.public_circuit_config.tx_idx_or_number_diff,
                            Rotation::cur(),
                        ),
                    ),
                ];
                v.append(
                    &mut (0..NUM_VALUES)
                        .map(|i| {
                            (
                                meta.query_advice(config.values[i], Rotation::cur()),
                                meta.query_instance(
                                    config.public_circuit_config.values[i],
                                    Rotation::cur(),
                                ),
                            )
                        })
                        .collect(),
                );
                v
            });
            config
        }
        #[rustfmt::skip]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.0.synthesize_sub(&config.public_circuit_config, &mut layouter)?;
            layouter.assign_region(
                || "TEST",
                |mut region| {
                    for (offset, row) in self.0.witness.public.iter().enumerate() {
                        assign_advice_or_fixed(&mut region, offset, &(row.tag as u8).into(), config.tag)?;
                        assign_advice_or_fixed(&mut region, offset, &row.tx_idx_or_number_diff.unwrap_or_default(), config.tx_idx_or_number_diff)?;
                        assign_advice_or_fixed(&mut region, offset, &row.value_0.unwrap_or_default(), config.values[0])?;
                        assign_advice_or_fixed(&mut region, offset, &row.value_1.unwrap_or_default(), config.values[1])?;
                        assign_advice_or_fixed(&mut region, offset, &row.value_2.unwrap_or_default(), config.values[2])?;
                        assign_advice_or_fixed(&mut region, offset, &row.value_3.unwrap_or_default(), config.values[3])?;
                    }
                    Ok(())
                },
            )        }
    }

    impl<F: Field> PublicTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self(PublicCircuit::new_from_witness(&witness))
        }
    }

    fn test_state_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(PublicCircuit::<Fp>::num_rows(&witness));
        let circuit = PublicTestCircuit::<Fp>::new(witness);
        let instance = circuit.0.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_state_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness =
            Witness::new(&geth_data_test(trace, &machine_code, &[], false, None));
        witness.print_csv();
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }
}
