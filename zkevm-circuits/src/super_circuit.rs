// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Super circuit is a circuit that puts all zkevm circuits together
use crate::arithmetic_circuit::{
    ArithmeticCircuit, ArithmeticCircuitConfig, ArithmeticCircuitConfigArgs,
};
use crate::bitwise_circuit::{BitwiseCircuit, BitwiseCircuitConfig, BitwiseCircuitConfigArgs};
use crate::bytecode_circuit::{BytecodeCircuit, BytecodeCircuitConfig, BytecodeCircuitConfigArgs};
use crate::copy_circuit::{CopyCircuit, CopyCircuitConfig, CopyCircuitConfigArgs};
use crate::core_circuit::{CoreCircuit, CoreCircuitConfig, CoreCircuitConfigArgs};
use crate::exp_circuit::{ExpCircuit, ExpCircuitConfig, ExpCircuitConfigArgs};
use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
#[cfg(not(feature = "no_hash_circuit"))]
use crate::keccak_circuit::{KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs};
use crate::public_circuit::{PublicCircuit, PublicCircuitConfig, PublicCircuitConfigArgs};
use crate::state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs};
use crate::table::{
    ArithmeticTable, BitwiseTable, BytecodeTable, CopyTable, ExpTable, FixedTable, KeccakTable,
    PublicTable, StateTable,
};
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::Witness;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

#[derive(Clone)]
pub struct SuperCircuitConfig<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    core_circuit: CoreCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    bytecode_circuit: BytecodeCircuitConfig<F>,
    state_circuit: StateCircuitConfig<F>,
    public_circuit: PublicCircuitConfig<F>,
    copy_circuit: CopyCircuitConfig<F>,
    fixed_circuit: FixedCircuitConfig<F>,
    bitwise_circuit: BitwiseCircuitConfig<F>,
    arithmetic_circuit: ArithmeticCircuitConfig<F>,
    exp_circuit: ExpCircuitConfig<F>,
    challenges: Challenges<halo2_proofs::plonk::Challenge>,
    #[cfg(not(feature = "no_hash_circuit"))]
    keccak_circuit: KeccakCircuitConfig<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> SubCircuitConfig<F>
    for SuperCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type ConfigArgs = ();

    fn new(meta: &mut ConstraintSystem<F>, _: Self::ConfigArgs) -> Self {
        // construct bytecode table
        let q_enable_bytecode = meta.complex_selector();
        let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);

        // construct state table
        let q_enable_state = meta.complex_selector();
        let state_table = StateTable::construct(meta, q_enable_state);

        // construct public table
        #[cfg(not(feature = "no_public_hash"))]
        let instance_hash = PublicTable::construct_hash_instance_column(meta);
        #[cfg(not(feature = "no_public_hash"))]
        let q_enable_public = meta.complex_selector();

        let public_table = PublicTable::construct(meta);

        // construct fixed table
        let fixed_table = FixedTable::construct(meta);
        let q_enable_arithmetic = meta.complex_selector();

        // construct arithmetic table
        let arithmetic_table = ArithmeticTable::construct(meta, q_enable_arithmetic);

        // construct copy table
        let q_enable_copy = meta.complex_selector();
        let copy_table = CopyTable::construct(meta, q_enable_copy);

        // construct bitwise table
        let q_enable_bitwise = meta.complex_selector();
        let bitwise_table = BitwiseTable::construct(meta, q_enable_bitwise);

        // construct exp table
        let exp_table = ExpTable::construct(meta);

        // construct keccak table
        let keccak_table = KeccakTable::construct(meta);

        // construct challenges after construct columns
        let challenges = Challenges::construct(meta);

        let core_circuit = CoreCircuitConfig::new(
            meta,
            CoreCircuitConfigArgs {
                bytecode_table,
                state_table,
                arithmetic_table,
                copy_table,
                bitwise_table,
                public_table,
                fixed_table,
                exp_table,
            },
        );
        let bytecode_circuit = BytecodeCircuitConfig::new(
            meta,
            BytecodeCircuitConfigArgs {
                q_enable: q_enable_bytecode,
                bytecode_table,
                fixed_table,
                keccak_table,
                public_table,
                challenges,
            },
        );
        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                q_enable: q_enable_state,
                state_table,
                fixed_table,
                challenges,
            },
        );

        #[cfg(not(feature = "no_public_hash"))]
        let public_circuit = PublicCircuitConfig::new(
            meta,
            PublicCircuitConfigArgs {
                q_enable: q_enable_public,
                public_table,
                keccak_table,
                challenges,
                instance_hash,
            },
        );

        #[cfg(feature = "no_public_hash")]
        let public_circuit =
            PublicCircuitConfig::new(meta, PublicCircuitConfigArgs { public_table });

        let copy_circuit = CopyCircuitConfig::new(
            meta,
            CopyCircuitConfigArgs {
                bytecode_table,
                state_table,
                public_table,
                copy_table,
                challenges,
            },
        );
        let fixed_circuit = FixedCircuitConfig::new(meta, FixedCircuitConfigArgs { fixed_table });
        let bitwise_circuit = BitwiseCircuitConfig::new(
            meta,
            BitwiseCircuitConfigArgs {
                fixed_table,
                bitwise_table,
            },
        );
        let arithmetic_circuit = ArithmeticCircuitConfig::new(
            meta,
            ArithmeticCircuitConfigArgs {
                q_enable: q_enable_arithmetic,
                arithmetic_table,
            },
        );

        let exp_circuit = ExpCircuitConfig::new(
            meta,
            ExpCircuitConfigArgs {
                arithmetic_table,
                exp_table,
            },
        );

        #[cfg(not(feature = "no_hash_circuit"))]
        let keccak_circuit = KeccakCircuitConfig::new(
            meta,
            KeccakCircuitConfigArgs {
                keccak_table,
                challenges,
            },
        );

        SuperCircuitConfig {
            core_circuit,
            bytecode_circuit,
            state_circuit,
            public_circuit,
            copy_circuit,
            fixed_circuit,
            bitwise_circuit,
            arithmetic_circuit,
            exp_circuit,
            challenges,
            #[cfg(not(feature = "no_hash_circuit"))]
            keccak_circuit,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<
    F: Field,
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    pub core_circuit: CoreCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW>,
    pub state_circuit: StateCircuit<F, MAX_NUM_ROW>,
    pub public_circuit: PublicCircuit<F, MAX_NUM_ROW>,
    pub copy_circuit: CopyCircuit<F, MAX_NUM_ROW>,
    pub fixed_circuit: FixedCircuit<F>,
    pub bitwise_circuit: BitwiseCircuit<F, MAX_NUM_ROW>,
    pub arithmetic_circuit: ArithmeticCircuit<F, MAX_NUM_ROW>,
    pub exp_circuit: ExpCircuit<F, MAX_NUM_ROW>,
    #[cfg(not(feature = "no_hash_circuit"))]
    pub keccak_circuit: KeccakCircuit<F, MAX_NUM_ROW>,
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > SubCircuit<F> for SuperCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type Config = SuperCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        let core_circuit = CoreCircuit::new_from_witness(witness);
        let bytecode_circuit = BytecodeCircuit::new_from_witness(witness);
        let state_circuit = StateCircuit::new_from_witness(witness);
        let public_circuit = PublicCircuit::new_from_witness(witness);
        let copy_circuit = CopyCircuit::new_from_witness(witness);
        let fixed_circuit = FixedCircuit::new_from_witness(witness);
        let bitwise_circuit = BitwiseCircuit::new_from_witness(witness);
        let arithmetic_circuit = ArithmeticCircuit::new_from_witness(witness);
        let exp_circuit = ExpCircuit::new_from_witness(witness);
        #[cfg(not(feature = "no_hash_circuit"))]
        let keccak_circuit = KeccakCircuit::new_from_witness(witness);
        Self {
            core_circuit,
            bytecode_circuit,
            state_circuit,
            public_circuit,
            copy_circuit,
            fixed_circuit,
            bitwise_circuit,
            arithmetic_circuit,
            exp_circuit,
            #[cfg(not(feature = "no_hash_circuit"))]
            keccak_circuit,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend(self.core_circuit.instance());
        instance.extend(self.bytecode_circuit.instance());
        instance.extend(self.state_circuit.instance());
        instance.extend(self.public_circuit.instance());
        instance.extend(self.copy_circuit.instance());
        instance.extend(self.fixed_circuit.instance());
        instance.extend(self.bitwise_circuit.instance());
        instance.extend(self.arithmetic_circuit.instance());
        instance.extend(self.exp_circuit.instance());
        #[cfg(not(feature = "no_hash_circuit"))]
        instance.extend(self.keccak_circuit.instance());
        instance
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        self.core_circuit
            .synthesize_sub(&config.core_circuit, layouter, challenges)?;
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, layouter, challenges)?;
        self.state_circuit
            .synthesize_sub(&config.state_circuit, layouter, challenges)?;
        self.public_circuit
            .synthesize_sub(&config.public_circuit, layouter, challenges)?;
        self.copy_circuit
            .synthesize_sub(&config.copy_circuit, layouter, challenges)?;
        // when feature `no_fixed_lookup` is on, we don't do synthesize
        #[cfg(not(feature = "no_fixed_lookup"))]
        self.fixed_circuit
            .synthesize_sub(&config.fixed_circuit, layouter, challenges)?;
        self.bitwise_circuit
            .synthesize_sub(&config.bitwise_circuit, layouter, challenges)?;
        self.arithmetic_circuit
            .synthesize_sub(&config.arithmetic_circuit, layouter, challenges)?;
        self.exp_circuit
            .synthesize_sub(&config.exp_circuit, layouter, challenges)?;
        #[cfg(not(feature = "no_hash_circuit"))]
        self.keccak_circuit
            .synthesize_sub(&config.keccak_circuit, layouter, challenges)?;
        Ok(())
    }

    fn unusable_rows() -> (usize, usize) {
        let unusable_rows = [
            CoreCircuit::<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows(),
            BytecodeCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            StateCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            PublicCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            CopyCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            BitwiseCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            ArithmeticCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            ExpCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            #[cfg(not(feature = "no_hash_circuit"))]
            KeccakCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
        ];
        let begin = itertools::max(unusable_rows.iter().map(|(begin, _end)| *begin)).unwrap();
        let end = itertools::max(unusable_rows.iter().map(|(_begin, end)| *end)).unwrap();
        (begin, end)
    }

    fn num_rows(witness: &Witness) -> usize {
        let mut num_rows = vec![
            CoreCircuit::<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::num_rows(witness),
            BytecodeCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            StateCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            PublicCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            CopyCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            BitwiseCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            ArithmeticCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            ExpCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            #[cfg(not(feature = "no_hash_circuit"))]
            KeccakCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
        ];

        // when feature `no_fixed_lookup` is on, we don't count the rows in fixed circuit
        #[cfg(not(feature = "no_fixed_lookup"))]
        num_rows.push(FixedCircuit::<F>::num_rows(witness));
        let num_rows_max = itertools::max(num_rows).unwrap();
        let (_num_padding_begin, num_padding_end) = Self::unusable_rows();
        assert!(
            num_rows_max + num_padding_end <= MAX_NUM_ROW,
            "Witness rows {} + end padding rows {} > Circuit max rows {}",
            num_rows_max,
            num_padding_end,
            MAX_NUM_ROW
        );
        let mut cs = ConstraintSystem::<F>::default();
        Self::configure(&mut cs);
        let minimum_rows = cs.minimum_rows();
        MAX_NUM_ROW + minimum_rows
    }
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > Circuit<F> for SuperCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type Config = SuperCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::new(meta, ())
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.challenges.values(&mut layouter);
        self.synthesize_sub(&config, &mut layouter, &challenges)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
    use crate::util::{chunk_data_test, log2_ceil};
    use halo2_proofs::dev::{CircuitCost, CircuitGates, MockProver};
    use halo2_proofs::halo2curves::bn256::{Fr, G1};

    fn test_super_circuit(
        witness: Witness,
    ) -> (
        u32,
        SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        MockProver<Fr>,
    ) {
        let k = log2_ceil(SuperCircuit::<
            Fr,
            MAX_NUM_ROW,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        >::num_rows(&witness));
        let circuit = SuperCircuit::new_from_witness(&witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        (k, circuit, prover)
    }

    #[test]
    #[cfg(feature = "evm")]
    fn test_from_test_data() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        let (_k, _circuit, prover) = test_super_circuit(witness);
        prover.assert_satisfied();
    }

    #[test]
    #[ignore]
    #[cfg(feature = "evm")]
    fn print_circuit_metrics() {
        // gates
        println!(
            "{} gates {}",
            vec!["#"; 20].join(""),
            vec!["#"; 20].join("")
        );
        let gates = CircuitGates::collect::<
            Fr,
            SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(());
        let str = gates.queries_to_csv();
        for line in str.lines() {
            let last_csv = line.rsplitn(2, ',').next().unwrap();
            println!("{}", last_csv);
        }

        println!(
            "{} costs {}",
            vec!["#"; 20].join(""),
            vec!["#"; 20].join("")
        );
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        let (k, circuit, _prover) = test_super_circuit(witness);
        let circuit_cost: CircuitCost<
            G1,
            SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        > = CircuitCost::measure(k as u32, &circuit);
        // let proof_size: usize = circuit_cost.proof_size(1).into();
        println!("Proof cost {:#?}", circuit_cost);

        println!(
            "{} lookups {}",
            vec!["#"; 20].join(""),
            vec!["#"; 20].join("")
        );
        let mut cs = ConstraintSystem::default();
        let _config =
            SuperCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::configure(&mut cs);
        for lookup in cs.lookups() {
            println!("{}: {:?}", lookup.name(), lookup);
        }
    }
}
