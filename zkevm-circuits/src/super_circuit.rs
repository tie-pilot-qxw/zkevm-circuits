//! Super circuit is a circuit that puts all zkevm circuits together
use crate::arithmetic_circuit::{ArithmeticCircuitConfig, ArithmeticCircuitConfigArgs};
use crate::bitwise_circuit::{BitwiseCircuit, BitwiseCircuitConfig, BitwiseCircuitConfigArgs};
use crate::bytecode_circuit::{BytecodeCircuit, BytecodeCircuitConfig, BytecodeCircuitConfigArgs};
use crate::copy_circuit::{CopyCircuit, CopyCircuitConfig, CopyCircuitConfigArgs};
use crate::core_circuit::{CoreCircuit, CoreCircuitConfig, CoreCircuitConfigArgs};
use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
use crate::public_circuit::{PublicCircuit, PublicCircuitConfig, PublicCircuitConfigArgs};
use crate::state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs};
use crate::table::{
    ArithmeticTable, BitwiseTable, BytecodeTable, CopyTable, FixedTable, PublicTable, StateTable,
};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::Witness;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
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
    public_circuit: PublicCircuitConfig,
    copy_circuit: CopyCircuitConfig<F>,
    fixed_circuit: FixedCircuitConfig<F>,
    bitwise_circuit: BitwiseCircuitConfig<F>,
    arithmetic_circuit: ArithmeticCircuitConfig<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> SubCircuitConfig<F>
    for SuperCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type ConfigArgs = ();

    fn new(meta: &mut ConstraintSystem<F>, _: Self::ConfigArgs) -> Self {
        let q_enable_bytecode = meta.complex_selector();
        let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
        let (instance_addr, instance_bytecode) =
            BytecodeTable::construct_addr_bytecode_instance_column(meta);
        let q_enable_state = meta.complex_selector();
        let state_table = StateTable::construct(meta, q_enable_state);
        let public_table = PublicTable::construct(meta);
        let fixed_table = FixedTable::construct(meta);
        let q_enable_arithmetic = meta.complex_selector();
        let arithmetic_table = ArithmeticTable::construct(meta, q_enable_arithmetic);
        let q_enable_copy = meta.complex_selector();
        let copy_table = CopyTable::construct(meta, q_enable_copy);
        let q_enable_bitwise = meta.complex_selector();
        let bitwise_table = BitwiseTable::construct(meta, q_enable_bitwise);
        let core_circuit = CoreCircuitConfig::new(
            meta,
            CoreCircuitConfigArgs {
                bytecode_table,
                state_table,
                arithmetic_table,
                copy_table,
                bitwise_table,
                public_table,
            },
        );
        let bytecode_circuit = BytecodeCircuitConfig::new(
            meta,
            BytecodeCircuitConfigArgs {
                q_enable: q_enable_bytecode,
                bytecode_table,
                fixed_table,
                instance_addr,
                instance_bytecode,
            },
        );
        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                q_enable: q_enable_state,
                state_table,
                fixed_table,
            },
        );
        let public_circuit =
            PublicCircuitConfig::new(meta, PublicCircuitConfigArgs { public_table });

        let copy_circuit = CopyCircuitConfig::new(
            meta,
            CopyCircuitConfigArgs {
                bytecode_table,
                state_table,
                public_table,
                copy_table,
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
        SuperCircuitConfig {
            core_circuit,
            bytecode_circuit,
            state_circuit,
            public_circuit,
            copy_circuit,
            fixed_circuit,
            bitwise_circuit,
            arithmetic_circuit,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<
    F: Field,
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    pub core_circuit: CoreCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW, MAX_CODESIZE>,
    pub state_circuit: StateCircuit<F, MAX_NUM_ROW>,
    pub public_circuit: PublicCircuit<F>,
    pub copy_circuit: CopyCircuit<F, MAX_NUM_ROW>,
    pub fixed_circuit: FixedCircuit<F>,
    pub bitwise_circuit: BitwiseCircuit<F, MAX_NUM_ROW>,
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const MAX_CODESIZE: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > SubCircuit<F>
    for SuperCircuit<F, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
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
        Self {
            core_circuit,
            bytecode_circuit,
            state_circuit,
            public_circuit,
            copy_circuit,
            fixed_circuit,
            bitwise_circuit,
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

        instance
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.core_circuit
            .synthesize_sub(&config.core_circuit, layouter)?;
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, layouter)?;
        self.state_circuit
            .synthesize_sub(&config.state_circuit, layouter)?;
        self.public_circuit
            .synthesize_sub(&config.public_circuit, layouter)?;
        self.copy_circuit
            .synthesize_sub(&config.copy_circuit, layouter)?;
        // when feature `no_fixed_lookup` is on, we don't do synthesize
        #[cfg(not(feature = "no_fixed_lookup"))]
        self.fixed_circuit
            .synthesize_sub(&config.fixed_circuit, layouter)?;
        self.bitwise_circuit
            .synthesize_sub(&config.bitwise_circuit, layouter)?;
        Ok(())
    }

    fn unusable_rows() -> (usize, usize) {
        let unusable_rows = [
            CoreCircuit::<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows(),
            BytecodeCircuit::<F, MAX_NUM_ROW, MAX_CODESIZE>::unusable_rows(),
            StateCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            PublicCircuit::<F>::unusable_rows(),
            CopyCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
            BitwiseCircuit::<F, MAX_NUM_ROW>::unusable_rows(),
        ];
        let begin = itertools::max(unusable_rows.iter().map(|(begin, _end)| *begin)).unwrap();
        let end = itertools::max(unusable_rows.iter().map(|(_begin, end)| *end)).unwrap();
        (begin, end)
    }

    fn num_rows(witness: &Witness) -> usize {
        let num_rows = vec![
            CoreCircuit::<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::num_rows(witness),
            BytecodeCircuit::<F, MAX_NUM_ROW, MAX_CODESIZE>::num_rows(witness),
            StateCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            PublicCircuit::<F>::num_rows(witness),
            CopyCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
            BitwiseCircuit::<F, MAX_NUM_ROW>::num_rows(witness),
        ];

        // when feature `no_fixed_lookup` is on, we don't count the rows in fixed circuit
        #[cfg(not(feature = "no_fixed_lookup"))]
        num_rows.push(FixedCircuit::<F>::num_rows(witness));
        let num_rows_max = itertools::max(num_rows).unwrap();
        assert!(
            num_rows_max <= MAX_NUM_ROW,
            "Witness rows {} > Circuit max rows {}",
            num_rows_max,
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
        const MAX_CODESIZE: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > Circuit<F>
    for SuperCircuit<F, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type Config = SuperCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
    type FloorPlanner = SimpleFloorPlanner;

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
        self.synthesize_sub(&config, &mut layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
    use crate::util::{geth_data_test, log2_ceil};
    use halo2_proofs::dev::{CircuitCost, CircuitGates, MockProver};
    use halo2_proofs::halo2curves::bn256::{Fr, G1};
    use std::fs::File;

    #[cfg(feature = "plot")]
    use plotters::prelude::*;

    fn test_super_circuit(
        witness: Witness,
    ) -> (
        u32,
        SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        MockProver<Fr>,
    ) {
        let k = log2_ceil(SuperCircuit::<
            Fr,
            MAX_NUM_ROW,
            MAX_CODESIZE,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        >::num_rows(&witness));
        let circuit = SuperCircuit::new_from_witness(&witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        (k, circuit, prover)
    }

    #[test]
    fn test_from_test_data() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        let mut buf = std::io::BufWriter::new(File::create("demo.html").unwrap());
        witness.write_html(&mut buf);
        let (_k, _circuit, prover) = test_super_circuit(witness);
        prover.assert_satisfied_par();
    }

    #[test]
    #[ignore]
    #[cfg(feature = "plot")]
    fn test_draw() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&geth_data_test(trace, &machine_code, &[], false));

        let (k, circuit, prover) = test_super_circuit(witness);
        // draw picture
        let root = BitMapBackend::new("layout_100x340.png", (1600, 900)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Example Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .view_width(0..340)
            .view_height(0..100)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(true)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(k, &circuit, &root)
            .unwrap();
    }

    #[test]
    #[ignore]
    fn print_circuit_metrics() {
        // gates
        println!(
            "{} gates {}",
            vec!["#"; 20].join(""),
            vec!["#"; 20].join("")
        );
        let gates = CircuitGates::collect::<
            Fr,
            SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >();
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
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        let (k, circuit, _prover) = test_super_circuit(witness);
        let circuit_cost: CircuitCost<
            G1,
            SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        > = CircuitCost::measure(k as usize, &circuit);
        // let proof_size: usize = circuit_cost.proof_size(1).into();
        println!("Proof cost {:#?}", circuit_cost);

        println!(
            "{} lookups {}",
            vec!["#"; 20].join(""),
            vec!["#"; 20].join("")
        );
        let mut cs = ConstraintSystem::default();
        let _config = SuperCircuit::<
            Fr,
            MAX_NUM_ROW,
            MAX_CODESIZE,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        >::configure(&mut cs);
        for lookup in cs.lookups() {
            println!("{}: {:?}", lookup, lookup);
        }
    }
}
