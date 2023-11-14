
use crate::execution::{ExecutionConfig, ExecutionGadgets, ExecutionState};
use crate::table::{BytecodeTable, LookupEntry, StateTable};

use crate::util::assign_advice_or_fixed;
use crate::util::{convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::copy::Row;
use crate::witness::Witness;
use eth_types::{Field, U256};

use halo2_proofs::circuit::{Layouter, Region, Value};

use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
#[derive(Clone)]
pub struct CopyCircuitConfig<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
{
    pub q_enable: Selector,
    /// The byte value that is copied
    pub byte: Column<Advice>,
    /// The source type, one of PublicCalldata, Memory, Bytecode, Calldata, Returndata
    pub src_type: Column<Advice>,
    /// The source id, tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: Column<Advice>,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: Column<Advice>,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: Column<Advice>,
    /// The destination type, one of Memory, Calldata, Returndata, PublicLog
    pub dst_type: Column<Advice>,
    /// The destination id, tx_idx for PublicLog, call_id for Memory, Calldata, Returndata
    pub dst_id: Column<Advice>,
    /// The destination pointer, for Calldata, Returndata, PublicLog means the index, for Memory means the address
    pub dst_pointer: Column<Advice>,
    /// The destination stamp, state stamp for Memory, Calldata, Returndata. As for PublicLog it means the log_stamp
    pub dst_stamp: Column<Advice>,
    /// The counter for one copy operation
    pub cnt: Column<Advice>,
    /// The length for one copy operation
    pub len: Column<Advice>,
    // Tables used for lookup
    bytecode_table: BytecodeTable<F>,
    state_table: StateTable,
    // todo add public_table
}

pub struct CopyCircuitConfigArgs<F> {
    pub bytecode_table: BytecodeTable<F>,
    pub state_table: StateTable,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> SubCircuitConfig<F>
    for CopyCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type ConfigArgs = CopyCircuitConfigArgs<F>;
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            bytecode_table,
            state_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let byte = meta.advice_column();
        let src_type = meta.advice_column();
        let src_id = meta.advice_column();
        let src_pointer = meta.advice_column();
        let src_stamp = meta.advice_column();
        let dst_type = meta.advice_column();
        let dst_id = meta.advice_column();
        let dst_pointer = meta.advice_column();
        let dst_stamp = meta.advice_column();
        let cnt = meta.advice_column();
        let len = meta.advice_column();
        let config = Self {
            q_enable,
            byte,
            src_type,
            src_id,
            src_pointer,
            src_stamp,
            dst_type,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            bytecode_table,
            state_table,
        };
        config
    }
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    CopyCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    #[rustfmt::skip]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {

        assign_advice_or_fixed(region, offset, &row.byte, self.byte)?;
        assign_advice_or_fixed(region, offset, &(row.src_type as u8).into(), self.src_type)?;
        assign_advice_or_fixed(region, offset, &row.src_id, self.src_id)?;
        assign_advice_or_fixed(region, offset, &row.src_pointer, self.src_pointer)?;
        assign_advice_or_fixed(region, offset, &row.src_stamp.unwrap(), self.src_stamp)?;
        assign_advice_or_fixed(region, offset, &(row.dst_type as u8).into(), self.dst_type)?;
        assign_advice_or_fixed(region, offset, &row.dst_id, self.dst_id)?;
        assign_advice_or_fixed(region, offset, &row.dst_pointer, self.dst_pointer)?;
        assign_advice_or_fixed(region, offset, &row.dst_stamp, self.dst_stamp)?;
        assign_advice_or_fixed(region, offset, &row.cnt, self.cnt)?;
        assign_advice_or_fixed(region, offset, &row.len, self.len)?;
        Ok(())
    }

    // assign a padding row whose state selector is the first `ExecutionState`
    // and auxiliary columns are kept from the last row
    #[rustfmt::skip]
    fn assign_padding_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        last_row: &Row,
    ) -> Result<(), Error> {

        assign_advice_or_fixed(region, offset, &U256::zero(), self.byte)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_type)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_pointer)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_stamp)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_type)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_pointer)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_stamp)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.cnt)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.len)?;     

        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        for (offset, row) in witness.copy.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }
        let last_row = witness
            .copy
            .last()
            .expect("copy witness must have last row");
        // pad the rest rows
        for offset in witness.core.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset, last_row)?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "COPY_byte", self.byte);
        region.name_column(|| "COPY_src_type", self.src_type);
        region.name_column(|| "COPY_src_id", self.src_id);
        region.name_column(|| "COPY_src_pointer", self.src_pointer);
        region.name_column(|| "COPY_src_stamp", self.src_stamp);
        region.name_column(|| "COPY_dst_type", self.dst_type);
        region.name_column(|| "COPY_dst_id", self.dst_id);
        region.name_column(|| "COPY_dst_pointer", self.dst_pointer);
        region.name_column(|| "COPY_dst_stamp", self.dst_stamp);
        region.name_column(|| "COPY_cnt", self.cnt);
        region.name_column(|| "COPY_len", self.len);

    }
}

#[derive(Clone, Default, Debug)]
pub struct CopyCircuit<
    F: Field,
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > SubCircuit<F> for CopyCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type Config = CopyCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        CopyCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "copy circuit",
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
        ExecutionGadgets::<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows()
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.copy.len()
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
    use crate::copy_circuit::CopyCircuit;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone, Default, Debug)]
    pub struct CopyTestCircuit<F: Field>(
        CopyCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    );

    impl<F: Field> Circuit<F> for CopyTestCircuit<F> {
        type Config = CopyCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let q_enable_state = meta.complex_selector();
            let state_table = StateTable::construct(meta, q_enable_state);
            Self::Config::new(
                meta,
                CopyCircuitConfigArgs {
                    bytecode_table,
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

    impl<F: Field> CopyTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self(CopyCircuit::new_from_witness(&witness))
        }
    }

    fn test_simple_copy_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CopyTestCircuit::<Fp>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[cfg(feature = "no_intersubcircuit_lookup")]
    #[test]
    fn test_core_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness = Witness::new(&geth_data_test(trace, &machine_code, &[], false));
        let prover = test_simple_copy_circuit(witness);
        prover.assert_satisfied_par();
    }
}