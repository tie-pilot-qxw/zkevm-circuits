//! Super circuit is a circuit that puts all zkevm circuits together

use crate::core_circuit::{CoreCircuit, CoreCircuitConfig, CoreCircuitConfigArgs};
use crate::table::{BytecodeTable, StackTable};
use crate::util::{SubCircuit, SubCircuitConfig};
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

#[derive(Copy, Clone)]
pub struct SuperCircuitConfig<F> {
    core_circuit: CoreCircuitConfig<F>,
    // stack_circuit: C
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs {}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = SuperCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let stack_table = StackTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta); //should share with bytecode circuit
        let core_circuit = CoreCircuitConfig::new(
            meta,
            CoreCircuitConfigArgs {
                stack_table,
                bytecode_table,
            },
        );
        SuperCircuitConfig { core_circuit }
    }
}

#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<F: Field> {
    pub core_circuit: CoreCircuit<F>,
}

impl<F: Field> SubCircuit<F> for SuperCircuit<F> {
    type Config = SuperCircuitConfig<F>;

    fn new_from_block() -> Self {
        let core_circuit = CoreCircuit::new_from_block();
        SuperCircuit { core_circuit }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.core_circuit.instance());

        instance
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn min_num_rows_block() -> (usize, usize) {
        todo!()
    }
}

impl<F: Field> Circuit<F> for SuperCircuit<F> {
    type Config = SuperCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::new(meta, SuperCircuitConfigArgs {})
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use plotters::prelude::*;

    #[test]
    fn empty_test() {
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block();
        let k = 6; //todo fill in
        let instance = vec![];
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            panic!("Verification failures: {:#?}", err);
        }
    }

    #[test]
    #[cfg(feature = "plot")]
    fn test_draw() {
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block();
        let k = 6; //todo fill in
                   // draw picture
        let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Example Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(k, &circuit, &root)
            .unwrap();
    }
}
