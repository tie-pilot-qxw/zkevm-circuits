use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{FixedTable, StateTable};
use crate::util::{assign_advice_or_fixed, SubCircuit, SubCircuitConfig};
use crate::witness::state::{Row, Tag};
use crate::witness::Witness;
use eth_types::Field;
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct StateCircuitConfig<F> {
    q_enable: Selector,
    /// Type of value, one of stack, memory, storage, call context, call data or return data
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    /// Stamp that increments for each state operation, unique for each row
    stamp: Column<Advice>,
    /// High 128-bit value of the row
    value_hi: Column<Advice>,
    /// Low 128-bit value of the row
    value_lo: Column<Advice>,
    /// Call id (other types) or contract address (storage type only)
    call_id_contract_addr: Column<Advice>,
    /// High 128-bit of the key (storage type only)
    pointer_hi: Column<Advice>,
    /// Low 128-bit of the key (storage type only) or call context tag
    /// Or stack pointer or memory address or data index (call data and return data)
    pointer_lo: Column<Advice>,
    /// Whether it is write or read, binary value
    is_write: Column<Advice>,
    _marker: PhantomData<F>,
}

pub struct StateCircuitConfigArgs {
    pub(crate) q_enable: Selector,
    pub(crate) state_table: StateTable,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            state_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let StateTable {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        } = state_table;
        let config: StateCircuitConfig<F> = Self {
            q_enable,
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
            _marker: PhantomData,
        };
        meta.create_gate("STATE_is_write_0_1", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_write = meta.query_advice(config.is_write, Rotation::cur());
            vec![q_enable * (1.expr() - is_write.clone()) * is_write]
        });
        config
    }
}

impl<F: Field> StateCircuitConfig<F> {
    #[rustfmt::skip]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let tag = BinaryNumberChip::construct(self.tag);
        assign_advice_or_fixed(region, offset, &row.stamp.unwrap_or_default(), self.stamp)?;
        assign_advice_or_fixed(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
        assign_advice_or_fixed(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
        assign_advice_or_fixed(region, offset, &row.call_id_contract_addr.unwrap_or_default(), self.call_id_contract_addr)?;
        assign_advice_or_fixed(region, offset, &row.pointer_hi.unwrap_or_default(), self.pointer_hi)?;
        assign_advice_or_fixed(region, offset, &row.pointer_lo.unwrap_or_default(), self.pointer_lo)?;
        assign_advice_or_fixed(region, offset, &row.is_write.unwrap_or_default(), self.is_write)?;
        tag.assign(region, offset, &row.tag.unwrap_or_default())?;

        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        for (offset, row) in witness.state.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }
        let last_row = witness
            .state
            .last()
            .expect("state witness must have last row");
        // pad the rest rows
        for offset in witness.state.len()..num_row_incl_padding {
            self.assign_row(region, offset, last_row)?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "STATE_value_hi", self.value_hi);
        region.name_column(|| "STATE_value_lo", self.value_lo);
        region.name_column(|| "STATE_stamp", self.stamp);
        region.name_column(|| "STATE_call_id_contract_addr", self.call_id_contract_addr);
        region.name_column(|| "STATE_pointer_hi", self.pointer_hi);
        region.name_column(|| "STATE_pointer_lo", self.pointer_lo);
        region.name_column(|| "STATE_is_write", self.is_write);
        self.tag.annotate_columns_in_region(region, "STATE");
    }
}

#[derive(Clone, Default, Debug)]
pub struct StateCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for StateCircuit<F, MAX_NUM_ROW> {
    type Config = StateCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        StateCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        mut layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "state circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;
                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (1, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        // bytecode witness length plus must-have padding in the end
        Self::unusable_rows().1 + witness.state.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone, Default, Debug)]
    pub struct StateTestCircuit<F: Field, const MAX_NUM_ROW: usize>(StateCircuit<F, MAX_NUM_ROW>);

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for StateTestCircuit<F, MAX_NUM_ROW> {
        type Config = StateCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable: Selector = meta.selector(); //todo complex?
            let state_table = StateTable::construct(meta, q_enable);
            Self::Config::new(
                meta,
                StateCircuitConfigArgs {
                    q_enable,
                    state_table,
                },
            )
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.0.synthesize_sub(&config, &mut layouter)
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> StateTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness) -> Self {
            Self(StateCircuit::new_from_witness(&witness))
        }
    }

    fn test_state_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = StateTestCircuit::<Fp, MAX_NUM_ROW>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[test]
    fn test_state_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness =
            Witness::new(&vec![trace], &geth_data_test(&machine_code, &[], false));
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }
}
