// use crate::util::{, SubCircuitConfig};

use crate::execution::ExecutionGadgets;
use crate::table::{BytecodeTable, StackTable};
use crate::util::{self, assign_advice_or_fixed};
use crate::util::{convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::core::Row;
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::dynamic_selector::{DynamicSelectorChip, DynamicSelectorConfig};
use gadgets::is_zero::IsZeroInstruction;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::circuit::{Region, SimpleFloorPlanner};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CoreCircuitConfig<
    F: Field,
    const CNT: usize,
    const NUM_HIGH: usize,
    const NUM_LOW: usize,
> {
    pub q_enable: Selector,
    // witness column of transaction index
    pub tx_idx: Column<Advice>,
    // witness column of call id
    pub call_id: Column<Advice>,
    // witness column of contract address
    pub code_addr: Column<Advice>,
    // witness column of program counter
    pub pc: Column<Advice>,
    // witness columns of opcode
    pub opcode: Column<Advice>,
    // witness column of opcode counter
    pub cnt: Column<Advice>,
    // witness columns of 32 versatile purposes
    pub vers: [Column<Advice>; 32],
    // IsZero chip for witness column cnt
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
    // Selector of execution state todo rename to execution state selector
    pub dynamic_selector: DynamicSelectorConfig<F, CNT, NUM_HIGH, NUM_LOW>,
    // Tables used for lookup
    bytecode_table: BytecodeTable<F>,
}
/*
impl<F: Field, const CNT: usize, const NUM_HIGH: usize, const NUM_LOW: usize>
    CoreCircuitConfig<F, CNT, NUM_HIGH, NUM_LOW>
{
    fn synthesize(
        &self,
        Core: &CoreCircuit<F, CNT, NUM_HIGH, NUM_LOW>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero);
        let dynamic_selector = DynamicSelectorChip::construct(self.dynamic_selector);
        layouter.assign_region(
            || "core",
            |mut region| {
                // annotate columns todo
                region.name_column(|| "cnt", self.cnt);
                for (offset, row) in Core.witness.core.iter().enumerate() {
                    region.assign_advice(
                        || "cnt",
                        self.cnt,
                        offset,
                        || Value::known(F::from_u128(row.cnt.as_u128())),
                    )?;
                    region.assign_advice(
                        || "tx_idx",
                        self.tx_idx,
                        offset,
                        || Value::known(F::from_u128(row.tx_idx.as_u128())),
                    )?;
                    region.assign_advice(
                        || "call_id",
                        self.call_id,
                        offset,
                        || Value::known(F::from_u128(row.call_id.as_u128())),
                    )?;
                    region.assign_advice(
                        || "code_addr",
                        self.code_addr,
                        offset,
                        || {
                            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                                &row.code_addr,
                            )))
                        },
                    )?;
                    region.assign_advice(
                        || "pc",
                        self.pc,
                        offset,
                        || Value::known(F::from_u128(row.pc.as_u128())),
                    )?;
                    region.assign_advice(
                        || "opcode",
                        self.opcode,
                        offset,
                        || Value::known(F::from_u128(row.opcode.as_u8() as u128)),
                    )?;
                    region.assign_advice(
                        || "vers_0",
                        self.vers[0],
                        offset,
                        || Value::known(F::from_u128(row.vers_0.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_1",
                        self.vers[1],
                        offset,
                        || Value::known(F::from_u128(row.vers_1.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_2",
                        self.vers[2],
                        offset,
                        || Value::known(F::from_u128(row.vers_2.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_3",
                        self.vers[3],
                        offset,
                        || Value::known(F::from_u128(row.vers_3.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_4",
                        self.vers[4],
                        offset,
                        || Value::known(F::from_u128(row.vers_4.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_5",
                        self.vers[5],
                        offset,
                        || Value::known(F::from_u128(row.vers_5.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_6",
                        self.vers[6],
                        offset,
                        || Value::known(F::from_u128(row.vers_2.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_7",
                        self.vers[7],
                        offset,
                        || Value::known(F::from_u128(row.vers_3.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_8",
                        self.vers[8],
                        offset,
                        || Value::known(F::from_u128(row.vers_8.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_9",
                        self.vers[9],
                        offset,
                        || Value::known(F::from_u128(row.vers_9.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_10",
                        self.vers[10],
                        offset,
                        || Value::known(F::from_u128(row.vers_10.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_11",
                        self.vers[11],
                        offset,
                        || Value::known(F::from_u128(row.vers_11.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_12",
                        self.vers[12],
                        offset,
                        || Value::known(F::from_u128(row.vers_12.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_13",
                        self.vers[13],
                        offset,
                        || Value::known(F::from_u128(row.vers_13.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_14",
                        self.vers[14],
                        offset,
                        || Value::known(F::from_u128(row.vers_14.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_15",
                        self.vers[15],
                        offset,
                        || Value::known(F::from_u128(row.vers_15.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_16",
                        self.vers[16],
                        offset,
                        || Value::known(F::from_u128(row.vers_16.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_17",
                        self.vers[17],
                        offset,
                        || Value::known(F::from_u128(row.vers_17.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_18",
                        self.vers[18],
                        offset,
                        || Value::known(F::from_u128(row.vers_18.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_19",
                        self.vers[19],
                        offset,
                        || Value::known(F::from_u128(row.vers_19.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_20",
                        self.vers[20],
                        offset,
                        || Value::known(F::from_u128(row.vers_20.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_21",
                        self.vers[21],
                        offset,
                        || Value::known(F::from_u128(row.vers_21.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_22",
                        self.vers[22],
                        offset,
                        || Value::known(F::from_u128(row.vers_22.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_23",
                        self.vers[23],
                        offset,
                        || Value::known(F::from_u128(row.vers_23.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_24",
                        self.vers[24],
                        offset,
                        || Value::known(F::from_u128(row.vers_24.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_25",
                        self.vers[25],
                        offset,
                        || Value::known(F::from_u128(row.vers_25.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_26",
                        self.vers[26],
                        offset,
                        || Value::known(F::from_u128(row.vers_26.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_27",
                        self.vers[27],
                        offset,
                        || Value::known(F::from_u128(row.vers_27.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_28",
                        self.vers[28],
                        offset,
                        || Value::known(F::from_u128(row.vers_28.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_29",
                        self.vers[29],
                        offset,
                        || Value::known(F::from_u128(row.vers_29.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_30",
                        self.vers[30],
                        offset,
                        || Value::known(F::from_u128(row.vers_30.unwrap_or_default().as_u128())),
                    )?;
                    region.assign_advice(
                        || "vers_31",
                        self.vers[31],
                        offset,
                        || Value::known(F::from_u128(row.vers_31.unwrap_or_default().as_u128())),
                    )?;

                    // do not enable first and last padding row
                    // todo what should be it
                    if offset > 2 && offset < (Core.witness.core).len() - 1 {
                        self.q_enable.enable(&mut region, offset)?;
                    }
                    cnt_is_zero.assign(
                        &mut region,
                        offset,
                        Value::known(F::from_u128(row.cnt.as_u128())),
                    )?;
                    // correctly assign the values
                    // dynamic_selector.assign(&mut region, offset, row.opcode.as_u8() as usize)?;
                }

                // todo assign dynamic selectors

                Ok(())
            },
        )
    }
}
*/
pub struct CoreCircuitConfigArgs<F> {
    pub q_enable: Selector,
    pub bytecode_table: BytecodeTable<F>,
} // todo change this

impl<F: Field, const CNT: usize, const NUM_HIGH: usize, const NUM_LOW: usize> SubCircuitConfig<F>
    for CoreCircuitConfig<F, CNT, NUM_HIGH, NUM_LOW>
{
    type ConfigArgs = CoreCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            bytecode_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let tx_idx = meta.advice_column();
        let call_id = meta.advice_column();
        let code_addr = meta.advice_column();
        let pc = meta.advice_column();
        let opcode = meta.advice_column();
        let cnt = meta.advice_column();

        let vers: [Column<Advice>; 32] = [(); 32]
            .iter()
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let dynamic_selector = DynamicSelectorChip::configure(
            meta,
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let ans = cnt_is_zero.expr_at(meta, Rotation::cur());
                q_enable * ans
            },
            vers[0..NUM_HIGH].try_into().unwrap(),
            vers[NUM_HIGH..NUM_HIGH + NUM_LOW].try_into().unwrap(),
        );

        meta.create_gate("Core Circuit counter", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let cnt_cur = meta.query_advice(cnt, Rotation::cur());
            let cnt_prev = meta.query_advice(cnt, Rotation::prev());
            let cnt_is_zero_prev = cnt_is_zero.expr_at(meta, Rotation::prev());
            vec![q_enable * (1.expr() - cnt_is_zero_prev) * (cnt_prev - cnt_cur - 1.expr())]
        });

        meta.create_gate("Program, Counter", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let pc_cur = meta.query_advice(pc, Rotation::cur());
            let pc_prev = meta.query_advice(pc, Rotation::prev());
            let cnt_is_zero_prev = cnt_is_zero.expr_at(meta, Rotation::prev());
            vec![q_enable * (1.expr() - cnt_is_zero_prev) * (pc_prev - pc_cur)]
        });

        let config = Self {
            q_enable,
            tx_idx,
            call_id,
            code_addr,
            pc,
            opcode,
            cnt,
            vers,
            cnt_is_zero,
            dynamic_selector,
            bytecode_table,
        };

        // tx_id, call_id, code_addr constraints?
        config
    }
}

impl<F: Field, const CNT: usize, const NUM_HIGH: usize, const NUM_LOW: usize>
    CoreCircuitConfig<F, CNT, NUM_HIGH, NUM_LOW>
{
    #[rustfmt::skip]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let cnt_is_zero: IsZeroWithRotationChip<F> = IsZeroWithRotationChip::construct(self.cnt_is_zero);
        assign_advice_or_fixed(region, offset, &row.tx_idx, self.tx_idx)?;
        assign_advice_or_fixed(region, offset, &row.call_id, self.call_id)?;
        assign_advice_or_fixed(region, offset, &row.code_addr, self.code_addr)?;
        assign_advice_or_fixed(region, offset, &row.pc, self.pc)?;
        assign_advice_or_fixed(region, offset, &row.opcode.as_u8().into(), self.opcode)?;
        assign_advice_or_fixed(region, offset, &row.cnt, self.cnt)?;
        assign_advice_or_fixed(region, offset, &row.vers_0.unwrap_or_default(), self.vers[0])?;
        assign_advice_or_fixed(region, offset, &row.vers_1.unwrap_or_default(), self.vers[1])?;
        assign_advice_or_fixed(region, offset, &row.vers_2.unwrap_or_default(), self.vers[2])?;
        assign_advice_or_fixed(region, offset, &row.vers_3.unwrap_or_default(), self.vers[3])?;
        assign_advice_or_fixed(region, offset, &row.vers_4.unwrap_or_default(), self.vers[4])?;
        assign_advice_or_fixed(region, offset, &row.vers_5.unwrap_or_default(), self.vers[5])?;
        assign_advice_or_fixed(region, offset, &row.vers_6.unwrap_or_default(), self.vers[6])?;
        assign_advice_or_fixed(region, offset, &row.vers_7.unwrap_or_default(), self.vers[7])?;
        assign_advice_or_fixed(region, offset, &row.vers_8.unwrap_or_default(), self.vers[8])?;
        assign_advice_or_fixed(region, offset, &row.vers_9.unwrap_or_default(), self.vers[9])?;
        assign_advice_or_fixed(region, offset, &row.vers_10.unwrap_or_default(), self.vers[10])?;
        assign_advice_or_fixed(region, offset, &row.vers_11.unwrap_or_default(), self.vers[11])?;
        assign_advice_or_fixed(region, offset, &row.vers_12.unwrap_or_default(), self.vers[12])?;
        assign_advice_or_fixed(region, offset, &row.vers_13.unwrap_or_default(), self.vers[13])?;
        assign_advice_or_fixed(region, offset, &row.vers_14.unwrap_or_default(), self.vers[14])?;
        assign_advice_or_fixed(region, offset, &row.vers_15.unwrap_or_default(), self.vers[15])?;
        assign_advice_or_fixed(region, offset, &row.vers_16.unwrap_or_default(), self.vers[16])?;
        assign_advice_or_fixed(region, offset, &row.vers_17.unwrap_or_default(), self.vers[17])?;
        assign_advice_or_fixed(region, offset, &row.vers_18.unwrap_or_default(), self.vers[18])?;
        assign_advice_or_fixed(region, offset, &row.vers_19.unwrap_or_default(), self.vers[19])?;
        assign_advice_or_fixed(region, offset, &row.vers_20.unwrap_or_default(), self.vers[20])?;
        assign_advice_or_fixed(region, offset, &row.vers_21.unwrap_or_default(), self.vers[21])?;
        assign_advice_or_fixed(region, offset, &row.vers_22.unwrap_or_default(), self.vers[22])?;
        assign_advice_or_fixed(region, offset, &row.vers_23.unwrap_or_default(), self.vers[23])?;
        assign_advice_or_fixed(region, offset, &row.vers_24.unwrap_or_default(), self.vers[24])?;
        assign_advice_or_fixed(region, offset, &row.vers_25.unwrap_or_default(), self.vers[25])?;
        assign_advice_or_fixed(region, offset, &row.vers_26.unwrap_or_default(), self.vers[26])?;
        assign_advice_or_fixed(region, offset, &row.vers_27.unwrap_or_default(), self.vers[27])?;
        assign_advice_or_fixed(region, offset, &row.vers_28.unwrap_or_default(), self.vers[28])?;
        assign_advice_or_fixed(region, offset, &row.vers_29.unwrap_or_default(), self.vers[29])?;
        assign_advice_or_fixed(region, offset, &row.vers_30.unwrap_or_default(), self.vers[30])?;
        assign_advice_or_fixed(region, offset, &row.vers_31.unwrap_or_default(), self.vers[31])?;
        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row.cnt,
            ))),
        )?;
        Ok(())
    }

    // assign a padding row whose state selector is 1,00000,1,000000 (it is not all 0)
    #[rustfmt::skip]
    fn assign_padding_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        let cnt_is_zero: IsZeroWithRotationChip<F> = IsZeroWithRotationChip::construct(self.cnt_is_zero);
        assign_advice_or_fixed(region, offset, &U256::zero(), self.tx_idx)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.call_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.code_addr)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.pc)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.opcode)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.cnt)?;
        for i in 0..32 {
            assign_advice_or_fixed(region, offset, &{
                if i==0 || i==NUM_HIGH {
                    U256::one()
                } else {
                    U256::zero()}
            }, self.vers[i])?;
        }
        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::ZERO),
        )?;
        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        for (offset, row) in witness.core.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }
        // pad the rest rows
        for offset in witness.core.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset)?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "CORE_tx_idx", self.tx_idx);
        region.name_column(|| "CORE_call_id", self.call_id);
        region.name_column(|| "CORE_code_addr", self.code_addr);
        region.name_column(|| "CORE_pc", self.pc);
        region.name_column(|| "CORE_opcode", self.opcode);
        region.name_column(|| "CORE_cnt", self.cnt);
        for i in 0..32 {
            region.name_column(|| format!("CORE_vers_{}", i), self.vers[i]);
        }
        self.cnt_is_zero
            .annotate_columns_in_region(region, "CORE_cnt_is_zero");
    }
}

#[derive(Clone, Default, Debug)]
pub struct CoreCircuit<
    F: Field,
    const MAX_NUM_ROW: usize,
    const CNT: usize,
    const NUM_HIGH: usize,
    const NUM_LOW: usize,
> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const CNT: usize,
        const NUM_HIGH: usize,
        const NUM_LOW: usize,
    > SubCircuit<F> for CoreCircuit<F, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>
{
    type Config = CoreCircuitConfig<F, CNT, NUM_HIGH, NUM_LOW>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        CoreCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "core circuit",
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

    // copy from bytecode circuit, may need to be modified
    fn unusable_rows() -> (usize, usize) {
        // Rotation in constrains has prev and but doesn't have next, so return 1,0
        // copy from bytecode circuit, may need to be modified
        (1, 0)
    }
    // copy from bytecode circuit, may need to be modified
    fn num_rows(witness: &Witness) -> usize {
        // bytecode witness length plus must-have padding in the end
        Self::unusable_rows().1 + witness.core.len()
    }
}

impl<
        F: Field,
        const MAX_NUM_ROW: usize,
        const CNT: usize,
        const NUM_HIGH: usize,
        const NUM_LOW: usize,
    > CoreCircuit<F, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>
{
    pub fn new(witness: Witness) -> Self {
        Self {
            witness,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_circuit::CoreCircuit;
    use crate::witness::core::Row;
    use crate::witness::Witness;
    use eth_types::evm_types::OpcodeId;

    use crate::util::log2_ceil;
    use eth_types::U256;
    use halo2_proofs::halo2curves::ff::FromUniformBytes;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr as Fp};

    const CNT: usize = 256;
    const NUM_HIGH: usize = 16;
    const NUM_LOW: usize = 16;
    #[derive(Clone, Default, Debug)]
    pub struct CoreTestCircuit<
        F: Field,
        const MAX_NUM_ROW: usize,
        const CNT: usize,
        const NUM_HIGH: usize,
        const NUM_LOW: usize,
    >(CoreCircuit<F, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>);

    impl<
            F: Field,
            const MAX_NUM_ROW: usize,
            const CNT: usize,
            const NUM_HIGH: usize,
            const NUM_LOW: usize,
        > Circuit<F> for CoreTestCircuit<F, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>
    {
        type Config = CoreCircuitConfig<F, CNT, NUM_HIGH, NUM_LOW>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let q_enable = meta.complex_selector();
            Self::Config::new(
                meta,
                CoreCircuitConfigArgs {
                    q_enable,
                    bytecode_table,
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

    impl<
            F: Field,
            const MAX_NUM_ROW: usize,
            const CNT: usize,
            const NUM_HIGH: usize,
            const NUM_LOW: usize,
        > CoreTestCircuit<F, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>
    {
        pub fn new(witness: Witness) -> Self {
            Self(CoreCircuit::new_from_witness(&witness))
        }

        pub fn instance(&self) -> Vec<Vec<F>> {
            self.0.instance()
        }
    }

    fn test_simple_core_circuit(witness: Witness) -> MockProver<Fp> {
        const MAX_NUM_ROW: usize = 245;
        let (num_padding_begin, _num_padding_end) =
            CoreCircuit::<Fp, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>::unusable_rows();
        let mut witness = witness;
        // insert padding rows (rows with all 0)
        for _ in 0..num_padding_begin {
            witness.core.insert(0, Default::default());
        }

        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CoreTestCircuit::<Fp, MAX_NUM_ROW, CNT, NUM_HIGH, NUM_LOW>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[test]
    fn test_core_circuit_with_three_correct_rows() {
        let row_0: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 2.into(),
            vers_0: Some(U256::from(0)),
            ..Default::default()
        };

        let row_1: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 1.into(),
            ..Default::default()
        };

        let row_2: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 0.into(),
            vers_0: Some(1.into()),  // dynamic seletor high is correct
            vers_17: Some(1.into()), // dynamic selector low is correct
            ..Default::default()
        };
        let mut witness = Witness {
            core: vec![row_0, row_1, row_2],
            ..Default::default()
        };
        let prover = test_simple_core_circuit(witness);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_core_circuit_with_three_false_rows() {
        let row_0: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 2.into(),
            vers_0: Some(U256::from(0)),
            ..Default::default()
        };

        let row_1: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 1.into(),
            ..Default::default()
        };

        let row_2: Row = Row {
            tx_idx: 1.into(),
            call_id: 1.into(),
            code_addr: U256::from_str_radix("ffffffffff", 16).unwrap(),
            pc: 1.into(),
            opcode: OpcodeId::ADD,
            cnt: 0.into(),
            vers_0: Some(1.into()),  // dynamic seletor high is correct
            vers_18: Some(2.into()), // dynamic selector low is false
            ..Default::default()
        };
        let mut witness = Witness {
            core: vec![row_0, row_1, row_2],
            ..Default::default()
        };
        let prover = test_simple_core_circuit(witness);
        assert!(prover.verify_par().is_err());
    }

    #[test]
    fn test_core_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness = Witness::new(&trace, &machine_code);
        test_simple_core_circuit(witness);
    }
}
