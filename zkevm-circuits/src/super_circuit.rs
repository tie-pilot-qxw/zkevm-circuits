//! Super circuit is a circuit that puts all zkevm circuits together

use crate::bytecode_circuit::{BytecodeCircuit, BytecodeCircuitConfig, BytecodeCircuitConfigArgs};
use crate::core_circuit::{CoreCircuit, CoreCircuitConfig, CoreCircuitConfigArgs};
use crate::stack_circuit::{StackCircuit, StackCircuitConfig, StackCircuitConfigArgs};
use crate::table::{BytecodeTable, FixedTable, StackTable};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::Block;
use eth_types::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

#[derive(Clone)]
pub struct SuperCircuitConfig<F> {
    core_circuit: CoreCircuitConfig<F>,
    stack_circuit: StackCircuitConfig<F>,
    bytecode_circuit: BytecodeCircuitConfig<F>,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs {}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = SuperCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
        let stack_table = StackTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let fixed_table = FixedTable::construct(meta);
        let core_circuit = CoreCircuitConfig::new(
            meta,
            CoreCircuitConfigArgs {
                stack_table,
                bytecode_table,
            },
        );
        let stack_circuit = StackCircuitConfig::new(
            meta,
            StackCircuitConfigArgs {
                stack_table,
                fixed_table,
            },
        );
        let bytecode_circuit =
            BytecodeCircuitConfig::new(meta, BytecodeCircuitConfigArgs { bytecode_table });
        SuperCircuitConfig {
            core_circuit,
            stack_circuit,
            bytecode_circuit,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<F: Field> {
    pub core_circuit: CoreCircuit<F>,
    pub stack_circuit: StackCircuit<F>,
    pub bytecode_circuit: BytecodeCircuit<F>,
}

impl<F: Field> SubCircuit<F> for SuperCircuit<F> {
    type Config = SuperCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let core_circuit = CoreCircuit::new_from_block(block);
        let stack_circuit = StackCircuit::new_from_block(block);
        let bytecode_circuit = BytecodeCircuit::new_from_block(block);
        SuperCircuit {
            core_circuit,
            stack_circuit,
            bytecode_circuit,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.core_circuit.instance());
        instance.extend_from_slice(&self.bytecode_circuit.instance());

        instance
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _layouter: &mut impl Layouter<F>,
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

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.core_circuit
            .synthesize_sub(&config.core_circuit, &mut layouter)?;
        self.stack_circuit
            .synthesize_sub(&config.stack_circuit, &mut layouter)?;
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, &mut layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{INPUT_BLOCK, INPUT_BLOCK_MUL, INPUT_BLOCK_SUB};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Instance;
    #[cfg(feature = "plot")]
    use plotters::prelude::*;

    #[test]
    fn test_super_circuit() {
        let k = 9;
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block(&*INPUT_BLOCK);
        let instance = vec![];
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            panic!("Verification failures: {:?}", err);
        }
    }

    #[test]
    fn test_SUB() {
        //k=4, panic NotEnoughRowsAvailable
        let k: u32 = 8;
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block(&*INPUT_BLOCK_SUB);
        let instance = vec![];
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            panic!("Verification failures: {:?}", err);
        }
    }

    #[test]
    fn test_MUL() {
        //k=4, panic NotEnoughRowsAvailable
        let k: u32 = 8;
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block(&*INPUT_BLOCK_MUL);
        let instance = vec![];
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            panic!("Verification failures: {:?}", err);
        }
    }

    #[test]
    #[ignore]
    #[cfg(feature = "plot")]
    fn test_draw() {
        let k = 8;
        let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block(&*INPUT_BLOCK_SUB);
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
