use crate::constant::NUM_VERS;
use crate::execution::{ExecutionConfig, ExecutionGadgets, ExecutionState};
use crate::table::{
    ArithmeticTable, BitwiseTable, BytecodeTable, CopyTable, LookupEntry, StateTable,
};
use crate::util::assign_advice_or_fixed;
use crate::util::{convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::core::Row;
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::dynamic_selector::{DynamicSelectorChip, DynamicSelectorConfig};
use gadgets::is_zero::IsZeroInstruction;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use strum::EnumCount;

#[allow(unused)]
#[derive(Clone)]
pub struct CoreCircuitConfig<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
{
    /// only enable for BEGIN_BLOCK
    pub q_first_exec_state: Selector,
    pub q_enable: Selector,
    /// Transaction index, the index inside the block, repeated for rows in one execution state
    pub tx_idx: Column<Advice>,
    /// Call id, unique for each call, repeated for rows in one execution state
    pub call_id: Column<Advice>,
    /// Contract code address, repeated for rows in one execution state
    pub code_addr: Column<Advice>,
    /// Program counter, repeated for rows in one execution state
    pub pc: Column<Advice>,
    /// The opcode, repeated for rows in one execution state
    pub opcode: Column<Advice>,
    /// Row counter, decremented for rows in one execution state
    pub cnt: Column<Advice>,
    /// Versatile columns that serve multiple purposes
    pub vers: [Column<Advice>; NUM_VERS],
    /// IsZero chip for column cnt
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// Dynamic selector for execution state
    pub execution_state_selector:
        DynamicSelectorConfig<F, { ExecutionState::COUNT }, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    /// Execution gadgets to constraint execution states
    execution_gadgets: ExecutionGadgets<NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    // Tables used for lookup
    bytecode_table: BytecodeTable<F>,
    state_table: StateTable,
    arithmetic_table: ArithmeticTable,
    copy_table: CopyTable,
    bitwise_table: BitwiseTable,
}

pub struct CoreCircuitConfigArgs<F> {
    pub bytecode_table: BytecodeTable<F>,
    pub state_table: StateTable,
    pub arithmetic_table: ArithmeticTable,
    pub copy_table: CopyTable,
    pub bitwise_table: BitwiseTable,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> SubCircuitConfig<F>
    for CoreCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type ConfigArgs = CoreCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            bytecode_table,
            state_table,
            arithmetic_table,
            copy_table,
            bitwise_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let q_first_exec_state = meta.selector();
        let tx_idx = meta.advice_column();
        let call_id = meta.advice_column();
        let code_addr = meta.advice_column();
        let pc = meta.advice_column();
        let opcode = meta.advice_column();
        let cnt = meta.advice_column();

        let vers: [Column<Advice>; NUM_VERS] = std::array::from_fn(|_| meta.advice_column());

        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let execution_state_selector = DynamicSelectorChip::configure(
            meta,
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let ans = cnt_is_zero.expr_at(meta, Rotation::cur());
                q_enable * ans
            },
            vers[0..NUM_STATE_HI_COL].try_into().unwrap(),
            vers[NUM_STATE_HI_COL..NUM_STATE_HI_COL + NUM_STATE_LO_COL]
                .try_into()
                .unwrap(),
        );

        let execution_config = ExecutionConfig {
            q_first_exec_state,
            q_enable,
            tx_idx,
            call_id,
            code_addr,
            pc,
            opcode,
            cnt,
            vers,
            cnt_is_zero,
            execution_state_selector,
            bytecode_table,
            state_table,
            arithmetic_table,
            copy_table,
            bitwise_table,
        };
        // all execution gadgets are created here
        let execution_gadgets = ExecutionGadgets::configure(meta, execution_config);
        let config = Self {
            q_first_exec_state,
            q_enable,
            tx_idx,
            call_id,
            code_addr,
            pc,
            opcode,
            cnt,
            vers,
            cnt_is_zero,
            execution_state_selector,
            execution_gadgets,
            bytecode_table,
            state_table,
            arithmetic_table,
            copy_table,
            bitwise_table,
        };

        meta.create_gate("CORE_cnt_decrement_unless_0", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            vec![q_enable * (1.expr() - cnt_is_zero_prev) * (cnt_prev - cnt - 1.expr())]
        });

        meta.create_gate("CORE_same_value_in_one_state", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let pc = meta.query_advice(config.pc, Rotation::cur());
            let pc_prev = meta.query_advice(config.pc, Rotation::prev());
            let opcode = meta.query_advice(config.opcode, Rotation::cur());
            let opcode_prev = meta.query_advice(config.opcode, Rotation::prev());
            let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
            let tx_idx_prev = meta.query_advice(config.tx_idx, Rotation::prev());
            let call_id = meta.query_advice(config.call_id, Rotation::cur());
            let call_id_prev = meta.query_advice(config.call_id, Rotation::prev());
            let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
            let code_addr_prev = meta.query_advice(config.code_addr, Rotation::prev());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            vec![
                (
                    "pc",
                    q_enable.clone() * (1.expr() - cnt_is_zero_prev.clone()) * (pc_prev - pc),
                ),
                (
                    "opcode",
                    q_enable.clone()
                        * (1.expr() - cnt_is_zero_prev.clone())
                        * (opcode_prev - opcode),
                ),
                (
                    "tx_idx",
                    q_enable.clone()
                        * (1.expr() - cnt_is_zero_prev.clone())
                        * (tx_idx_prev - tx_idx),
                ),
                (
                    "call_id",
                    q_enable.clone()
                        * (1.expr() - cnt_is_zero_prev.clone())
                        * (call_id_prev - call_id),
                ),
                (
                    "code_addr",
                    q_enable * (1.expr() - cnt_is_zero_prev) * (code_addr_prev - code_addr),
                ),
            ]
        });

        meta.lookup_any("CORE_bytecode", |meta| {
            let entry = LookupEntry::Bytecode {
                addr: meta.query_advice(config.code_addr, Rotation::cur()),
                pc: meta.query_advice(config.pc, Rotation::cur()),
                opcode: meta.query_advice(config.opcode, Rotation::cur()),
            };
            let lookup_vec = config.bytecode_table.get_lookup_vector(meta, entry);
            lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(config.q_enable);
                    (q_enable * left, right)
                })
                .collect()
        });
        config
    }
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    CoreCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
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
        for (i, value) in [
            &row.vers_0, &row.vers_1, &row.vers_2, &row.vers_3, &row.vers_4,
            &row.vers_5, &row.vers_6, &row.vers_7, &row.vers_8, &row.vers_9,
            &row.vers_10, &row.vers_11, &row.vers_12, &row.vers_13, &row.vers_14,
            &row.vers_15, &row.vers_16, &row.vers_17, &row.vers_18, &row.vers_19,
            &row.vers_20, &row.vers_21, &row.vers_22, &row.vers_23, &row.vers_24,
            &row.vers_25, &row.vers_26, &row.vers_27, &row.vers_28, &row.vers_29,
            &row.vers_30, &row.vers_31,
        ].into_iter().enumerate() {
            assign_advice_or_fixed(region, offset, &value.unwrap_or_default(), self.vers[i])?;
        }
        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row.cnt,
            ))),
        )?;
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
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero);
        assign_advice_or_fixed(region, offset, &U256::zero(), self.tx_idx)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.call_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.code_addr)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.pc)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.opcode)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.cnt)?;
        // assign execution selector state, the first state
        for i in 0..NUM_STATE_HI_COL + NUM_STATE_LO_COL {
            assign_advice_or_fixed(
                region,
                offset,
                &{
                    if i == 0 || i == NUM_STATE_HI_COL { U256::one() } else { U256::zero() }
                },
                self.vers[i],
            )?;
        }
        // assign auxiliary, values are kept from the last row
        for (i, value) in (NUM_STATE_HI_COL + NUM_STATE_LO_COL..NUM_VERS).zip(
            [&last_row.vers_20, &last_row.vers_21, &last_row.vers_22, &last_row.vers_23, &last_row.vers_24,
                &last_row.vers_25, &last_row.vers_26, &last_row.vers_27, &last_row.vers_28, &last_row.vers_29,
                &last_row.vers_30, &last_row.vers_31]) {
            assign_advice_or_fixed(
                region,
                offset,
                &value.unwrap_or_default(),
                self.vers[i],
            )?;
        }
        cnt_is_zero.assign(region, offset, Value::known(F::ZERO))?;
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
        let last_row = witness
            .core
            .last()
            .expect("core witness must have last row");
        // pad the rest rows
        for offset in witness.core.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset, last_row)?;
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
        for i in 0..NUM_VERS {
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
    > SubCircuit<F> for CoreCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    type Config = CoreCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        CoreCircuit {
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
            || "core circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;
                // because index start from 0
                config
                    .q_first_exec_state
                    .enable(&mut region, CoreCircuit::<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows().0)?;
                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        ExecutionGadgets::<NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows::<F>()
        //todo add other values
    }

    fn num_rows(witness: &Witness) -> usize {
        // bytecode witness length plus must-have padding in the end
        Self::unusable_rows().1 + witness.core.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
    use crate::core_circuit::CoreCircuit;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::bytecode;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct CoreTestCircuitConfig<F: Field> {
        pub core_circuit: CoreCircuitConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        pub bytecode_table: BytecodeTable<F>,
        pub state_table: StateTable,
        pub arithmetic_table: ArithmeticTable,
        pub copy_table: CopyTable,
        pub bitwise_table: BitwiseTable,
    }
    #[derive(Clone, Default, Debug)]
    pub struct CoreTestCircuit<F: Field> {
        core_circuit: CoreCircuit<F, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        witness: Witness,
    }

    impl<F: Field> Circuit<F> for CoreTestCircuit<F> {
        type Config = CoreTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let q_enable_state = meta.complex_selector();
            let state_table = StateTable::construct(meta, q_enable_state);
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
                },
            );
            Self::Config {
                core_circuit,
                bytecode_table,
                state_table,
                arithmetic_table,
                copy_table,
                bitwise_table,
            }

            // let q_enable_bytecode = meta.complex_selector();
            // let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            // let q_enable_state = meta.complex_selector();
            // let state_table = StateTable::construct(meta, q_enable_state);
            // let core_circuit = CoreCircuitConfig::new(
            //     meta,
            //     CoreCircuitConfigArgs {
            //         bytecode_table,
            //         state_table,
            //     },
            // )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.core_circuit
                .synthesize_sub(&config.core_circuit, &mut layouter)?;
            // assign bytecode table, but do not enable selector, since we are not testing it here
            layouter.assign_region(
                || "test, bytecode circuit",
                |mut region| {
                    config
                        .bytecode_table
                        .assign_with_region(&mut region, &self.witness)
                },
            )?;
            // assign state table, but do not enable selector, since we are not testing it here
            layouter.assign_region(
                || "test, state circuit",
                |mut region| {
                    config
                        .state_table
                        .assign_with_region(&mut region, &self.witness)
                },
            )?;
            // assign arithmetic table, but do not enable selector, since we are not testing it here
            layouter.assign_region(
                || "test, arithmetic circuit",
                |mut region| {
                    config
                        .arithmetic_table
                        .assign_with_region(&mut region, &self.witness)
                },
            )?;
            //  assign copy table, but do not enable selector, since we are not testing it here
            layouter.assign_region(
                || "test, copy circuit",
                |mut region| {
                    config
                        .copy_table
                        .assign_with_region(&mut region, &self.witness)
                },
            )?;
            //  assign bitwise table, but do not enable selector, since we are not testing it here
            layouter.assign_region(
                || "test, bitwise circuit",
                |mut region| {
                    config
                        .bitwise_table
                        .assign_with_region(&mut region, &self.witness)
                },
            )?;
            Ok(())
        }
    }

    impl<F: Field> CoreTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self {
                core_circuit: CoreCircuit::new_from_witness(&witness),
                witness: witness.clone(),
            }
        }
    }

    fn test_simple_core_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CoreTestCircuit::<Fp>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[test]
    fn test_core_parser() {
        let code = bytecode! {
            PUSH1(1)
            PUSH1(2)
            ADD
            STOP
        };
        let machine_code = code.to_vec();
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        let prover = test_simple_core_circuit(witness);
        prover.assert_satisfied_par();
    }
}
