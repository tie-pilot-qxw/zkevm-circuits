//! wrapping of mpt-circuit

use crate::constant::POSEIDON_HASH_BYTES_IN_FIELD;
use crate::util::convert_u256_to_64_bytes;
use crate::witness::Witness;
use crate::{
    table::PoseidonTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};
use poseidon_circuit::hash::{PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};
use std::marker::PhantomData;

/// re-wrapping for mpt circuit
#[derive(Default, Clone, Debug)]
pub struct PoseidonCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

/// Circuit configuration argument ts
pub struct PoseidonCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
}

/// re-wrapping for poseidon config
#[derive(Debug, Clone)]
pub struct PoseidonCircuitConfig<F: Field>(pub(crate) PoseidonHashConfig<F>);

pub const HASH_BLOCK_STEP_SIZE: usize = POSEIDON_HASH_BYTES_IN_FIELD * PoseidonTable::INPUT_WIDTH;

impl<F: Field> SubCircuitConfig<F> for PoseidonCircuitConfig<F> {
    type ConfigArgs = PoseidonCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { poseidon_table }: Self::ConfigArgs,
    ) -> Self {
        let poseidon_table = (
            poseidon_table.q_enable,
            [
                poseidon_table.hash_id,
                poseidon_table.input_0,
                poseidon_table.input_1,
                poseidon_table.control,
                poseidon_table.domain_spec,
                poseidon_table.heading_mark,
            ],
        );
        let conf = PoseidonHashConfig::configure_sub(meta, poseidon_table, HASH_BLOCK_STEP_SIZE);
        Self(conf)
    }
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for PoseidonCircuit<F, MAX_NUM_ROW> {
    type Config = PoseidonCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        PoseidonCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // MAX_NUM_ROW 对应circuits_params.max_poseidon_rows，由于 MAX_NUM_ROW 表示的是全局电路的最大行数，
        // 这里仍然需要考虑取值的正确性，这里正确的被除数理论上应该要小于MAX_NUM_ROW
        let max_hashes = MAX_NUM_ROW / F::hash_block_size();
        assert!(self.witness.poseidon.len() < max_hashes);

        let mut inputs = Vec::new();
        let mut controls = Vec::new();
        let mut domain = Vec::new();
        let mut checks = Vec::new();

        for row in self.witness.poseidon.iter() {
            inputs.push([
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.input_0)),
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.input_1)),
            ]);
            controls.push(row.control);
            let domain_field = if let Some(domain) = &row.domain {
                Some(F::from_uniform_bytes(&convert_u256_to_64_bytes(domain)))
            } else {
                None
            };
            domain.push(domain_field);
            let check_filed = if let Some(check) = &row.check {
                Some(F::from_uniform_bytes(&convert_u256_to_64_bytes(check)))
            } else {
                None
            };
            checks.push(check_filed);
        }

        let poseidon_table = PoseidonHashTable::<F> {
            inputs,
            controls,
            domain,
            checks,
        };

        let chip = PoseidonHashChip::<_, HASH_BLOCK_STEP_SIZE>::construct(
            config.0.clone(),
            &poseidon_table,
            max_hashes,
        );

        chip.load(layouter)
    }

    fn unusable_rows() -> (usize, usize) {
        (1, 256)
    }

    /// 最少需要的行数
    fn num_rows(witness: &Witness) -> usize {
        witness.poseidon.len() * F::hash_block_size()
    }
}

#[cfg(test)]
mod test {
    use crate::poseidon_circuit::{
        PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs,
    };
    use crate::table::PoseidonTable;
    use crate::util::{hash_code_poseidon, Challenges, SubCircuit, SubCircuitConfig};
    use crate::witness::poseidon::{
        get_hash_input_from_u8s_default, get_poseidon_row_from_stream_input,
    };
    use crate::witness::Witness;
    use eth_types::Field;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::{CircuitCost, MockProver};
    use halo2_proofs::halo2curves::bn256::{Fr, G1};
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use poseidon_circuit::Hashable;

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for PoseidonCircuit<F, MAX_NUM_ROW> {
        type Config = (PoseidonCircuitConfig<F>, Challenges);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let challenges = Challenges::construct(meta);
            let poseidon_table = PoseidonTable::construct(meta);

            let config =
                { PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table }) };

            (config, challenges)
        }

        fn synthesize(
            &self,
            (config, challenges): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = challenges.values(&mut layouter);
            self.synthesize_sub(&config, &mut layouter, &challenges)
        }
    }

    #[test]
    fn test_poseidon_circuit_metrics() {
        println!("hash_block_size:{}", Fr::hash_block_size());
        let code = vec![1u8; 1];
        let unrolled_inputs = get_hash_input_from_u8s_default::<Fr>(code.iter().copied());
        let rows =
            get_poseidon_row_from_stream_input(&unrolled_inputs, None, code.len() as u64, 62);
        let witness = Witness {
            poseidon: rows,
            ..Default::default()
        };

        let poseidon_circuit = PoseidonCircuit::new_from_witness(&witness);
        let circuit_cost: CircuitCost<G1, PoseidonCircuit<Fr, 1000>> =
            CircuitCost::measure(10u32, &poseidon_circuit);
        println!("Proof cost {:#?}", circuit_cost);
    }

    #[test]
    fn test_poseidon_circuit() {
        let code = vec![1u8; 1];
        let unrolled_inputs = get_hash_input_from_u8s_default::<Fr>(code.iter().copied());
        let hash_expect = hash_code_poseidon(&code);
        let rows = get_poseidon_row_from_stream_input(
            &unrolled_inputs,
            Some(hash_expect),
            code.len() as u64,
            62,
        );
        let witness = Witness {
            poseidon: rows,
            ..Default::default()
        };

        let poseidon_circuit: PoseidonCircuit<Fr, 1000> =
            PoseidonCircuit::new_from_witness(&witness);
        let instance = poseidon_circuit.instance();
        let prover = MockProver::<Fr>::run(10, &poseidon_circuit, instance).unwrap();
        prover.assert_satisfied()
    }
}
