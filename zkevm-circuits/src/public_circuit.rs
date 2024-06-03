use crate::constant::PUBLIC_NUM_VALUES;
use crate::table::PublicTable;
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::Witness;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Instance};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct PublicCircuitConfig {
    // tag can be ChainId,BlockCoinbase....; refer witness/public.rs
    tag: Column<Instance>,
    /// block_tx_idx generally represents either block_idx or tx_idx.
    /// When representing tx_idx, it equals to block_idx * 2^32 + tx_idx.
    /// Except for tag=BlockHash, means max_block_idx.
    block_tx_idx: Column<Instance>,
    // values , 4 columns
    values: [Column<Instance>; PUBLIC_NUM_VALUES],
}

pub struct PublicCircuitConfigArgs {
    // refer table.rs PublicTable
    pub public_table: PublicTable,
}

impl<F: Field> SubCircuitConfig<F> for PublicCircuitConfig {
    type ConfigArgs = PublicCircuitConfigArgs;

    fn new(
        _meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { public_table }: Self::ConfigArgs,
    ) -> Self {
        // unwrap public_table
        let PublicTable {
            // tag can be ChainId,BlockCoinbase....; refer witness/public.rs
            tag,
            // block_tx_idx (start from 1), except for tag=BlockHash, means recent block number diff (1...256)
            block_tx_idx,
            // values , 4 columns
            values,
        } = public_table;
        Self {
            tag,
            block_tx_idx,
            values,
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
    // instance return vector of vector
    /// +-----+-----------------------+--------+--------+--------+--------+
    /// | tag | block_tx_idx | value0 | value1 | value2 | value3 |
    fn instance(&self) -> Vec<Vec<F>> {
        self.witness.get_public_instance()
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // all instance column , do nothing
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
    use crate::constant::MAX_NUM_ROW;
    use crate::util::{assign_advice_or_fixed_with_u256, chunk_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Advice, Circuit};
    use halo2_proofs::poly::Rotation;

    #[derive(Clone, Default, Debug)]
    pub struct PublicTestCircuit<F: Field>(PublicCircuit<F>);
    #[derive(Clone)]
    pub struct PublicTestCircuitConfig {
        pub public_circuit_config: PublicCircuitConfig,
        pub tag: Column<Advice>,
        pub block_tx_idx: Column<Advice>,
        pub values: [Column<Advice>; PUBLIC_NUM_VALUES],
        pub challenges: Challenges,
    }

    impl<F: Field> Circuit<F> for PublicTestCircuit<F> {
        type Config = PublicTestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // _dummy_cols for challenge
            let _dummy_cols = meta.advice_column();
            let public_table = PublicTable::construct(meta);
            let challenges = Challenges::construct(meta);
            let public_circuit_config =
                PublicCircuitConfig::new(meta, PublicCircuitConfigArgs { public_table });
            let config = PublicTestCircuitConfig {
                public_circuit_config,
                tag: meta.advice_column(),
                block_tx_idx: meta.advice_column(),
                values: std::array::from_fn(|_| meta.advice_column()),
                challenges,
            };
            // lookup constraints
            meta.lookup_any("test lookup", |meta| {
                let mut v = vec![
                    // tag lookup constraints
                    (
                        // query tag advice
                        meta.query_advice(config.tag, Rotation::cur()),
                        // query tag instance
                        meta.query_instance(config.public_circuit_config.tag, Rotation::cur()),
                    ),
                    // block_tx_idx lookup constraints
                    (
                        // query block_tx_idx advice
                        meta.query_advice(config.block_tx_idx, Rotation::cur()),
                        // query block_tx_idx instance
                        meta.query_instance(
                            config.public_circuit_config.block_tx_idx,
                            Rotation::cur(),
                        ),
                    ),
                ];
                // values lookup constraints
                v.append(
                    &mut (0..PUBLIC_NUM_VALUES)
                        .map(|i| {
                            (
                                // query value advice
                                meta.query_advice(config.values[i], Rotation::cur()),
                                // query value instance
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
            let challenges = config.challenges.values(&mut layouter);
            self.0.synthesize_sub(&config.public_circuit_config, &mut layouter,&challenges)?;
            // assign values 
            layouter.assign_region(
                || "TEST",
                |mut region| {
                    for (offset, row) in self.0.witness.public.iter().enumerate() {
                        assign_advice_or_fixed_with_u256(&mut region, offset, &(row.tag as u8).into(), config.tag)?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.block_tx_idx.unwrap_or_default(), config.block_tx_idx)?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_0.unwrap_or_default(), config.values[0])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_1.unwrap_or_default(), config.values[1])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_2.unwrap_or_default(), config.values[2])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_3.unwrap_or_default(), config.values[3])?;
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

    fn test_public_circuit(witness: Witness) -> MockProver<Fp> {
        // ceiling of log2(MAX_NUM_ROW)
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = PublicTestCircuit::<Fp>::new(witness);
        // get circuit instances , vec<vec<Fr>>
        let instance = circuit.0.instance();
        // mock run circuit
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_public_parser() {
        // load instructions
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        // parse trace
        let trace = trace_parser::trace_program(&machine_code, &[]);
        // construct witness using trace
        let witness: Witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        // output witness as csv
        witness.print_csv();
        // witness prove
        let prover = test_public_circuit(witness);
        // any circuit fail will panic
        prover.assert_satisfied_par();
    }
}
