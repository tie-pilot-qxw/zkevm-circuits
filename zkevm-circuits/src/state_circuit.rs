pub mod multiple_precision_integer;
pub mod ordering;

use self::ordering::Config as OrderingConfig;
use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{FixedTable, StateTable};
use crate::util::{assign_advice_or_fixed, SubCircuit, SubCircuitConfig};
use crate::witness::state::{Row, Tag};
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::poly::Rotation;
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig};
use ordering::{LimbIndex, CALLID_OR_ADDRESS_LIMBS, POINTER_LIMBS, STAMP_LIMBS};
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
    /// Sort the state and calculate whether the current state is accessed for the first time.
    /// sorted elements(tag, call_id_or_address, pointer_hi/_lo, stamp).
    ordering_config: OrderingConfig,
    /// Elements will be sorted in the state circuit
    sort_keys: SortedElements,
    /// Indicates whether the location is visited for the first time;
    /// 0 if the difference between the state row is Stamp0|Stamp1, otherwise is 1.
    is_first_access: Column<Advice>,
    /// Lookup table for some information，such as value of cell U16/U0/U8 range lookup.
    fixed_table: FixedTable,
    _marker: PhantomData<F>,
}

pub struct StateCircuitConfigArgs {
    pub(crate) q_enable: Selector,
    pub(crate) state_table: StateTable,
    pub(crate) fixed_table: FixedTable,
}

#[derive(Clone, Copy, Debug)]
pub struct SortedElements {
    tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    call_id_or_address: MpiConfig<U256, CALLID_OR_ADDRESS_LIMBS>,
    pointer_hi: MpiConfig<U256, POINTER_LIMBS>,
    pointer_lo: MpiConfig<U256, POINTER_LIMBS>,
    stamp: MpiConfig<u32, STAMP_LIMBS>,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            state_table,
            fixed_table,
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

        // new sorted element with Advice that will be sorted
        let mpi_call_id = MpiChip::configure(meta, q_enable, call_id_contract_addr, fixed_table);
        let mpi_pointer_hi = MpiChip::configure(meta, q_enable, pointer_hi, fixed_table);
        let mpi_pointer_lo = MpiChip::configure(meta, q_enable, pointer_lo, fixed_table);
        let mpi_stamp = MpiChip::configure(meta, q_enable, stamp, fixed_table);
        let keys = SortedElements {
            tag,
            call_id_or_address: mpi_call_id,
            pointer_hi: mpi_pointer_hi,
            pointer_lo: mpi_pointer_lo,
            stamp: mpi_stamp,
        };
        // Passes the element to be sorted as a parameter to the sorting function
        let ordering_config = OrderingConfig::new(meta, q_enable, keys, fixed_table);
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
            sort_keys: keys,
            ordering_config,
            is_first_access: meta.advice_column(),
            fixed_table,
            _marker: PhantomData,
        };

        // create custom gate with different column and rotation
        meta.create_gate("STATE_constraint_in_different_region", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_first_access = meta.query_advice(config.is_first_access, Rotation::cur());
            let stack_condition = config.tag.value_equals(Tag::Stack, Rotation::cur())(meta);
            let memory_condition = config.tag.value_equals(Tag::Memory, Rotation::cur())(meta);
            let _storage_condition = config.tag.value_equals(Tag::Storage, Rotation::cur())(meta);
            let callcontext_condition =
                config.tag.value_equals(Tag::CallContext, Rotation::cur())(meta);
            let calldata_condition = config.tag.value_equals(Tag::CallData, Rotation::cur())(meta);
            let return_condition = config.tag.value_equals(Tag::ReturnData, Rotation::cur())(meta);
            let pointer_hi = meta.query_advice(config.pointer_hi, Rotation::cur());
            let prev_value_hi = meta.query_advice(config.value_hi, Rotation::prev());
            let prev_value_lo = meta.query_advice(config.value_lo, Rotation::prev());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let is_write = meta.query_advice(config.is_write, Rotation::cur());

            let mut vec = vec![
                // is_write = 0/1
                (
                    "is_write",
                    q_enable.clone() * (1.expr() - is_write.clone()) * is_write.clone(),
                ),
                // is_first_access = 0/1
                (
                    "first_access",
                    q_enable.clone()
                        * (1.expr() - is_first_access.clone())
                        * is_first_access.clone(),
                ),
                //1. first_access=1 => is_write=1
                //2. pointer_hi=0
                (
                    "stack_first_access",
                    q_enable.clone()
                        * stack_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "stack_pointer_hi",
                    q_enable.clone() * stack_condition * pointer_hi.clone(),
                ),
                //1. first_access=1 & is_write=0 => value=0
                //2. pointer_hi=0
                (
                    "memory_first_access_value_lo",
                    q_enable.clone()
                        * memory_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone())
                        * value_lo.clone(),
                ),
                (
                    "memory_value_hi",
                    q_enable.clone() * memory_condition.clone() * value_hi.clone(),
                ),
                (
                    "memory_pointer_hi",
                    q_enable.clone() * memory_condition * pointer_hi.clone(),
                ),
                // TODO storage first_access=1 & is_write=0 & MPT check

                //1. first_access=1 => is_write=1
                //2. pointer_hi=0
                (
                    "callcontext_first_access",
                    q_enable.clone()
                        * callcontext_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "callcontext_pointer_hi",
                    q_enable.clone() * callcontext_condition.clone() * pointer_hi.clone(),
                ),
                //1. first_access=1 & is_write=0 => value_lo=0
                //2. value_hi=0
                //3. pointer_hi=0
                (
                    "calldata_first_access_write_value_lo",
                    q_enable.clone()
                        * calldata_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone())
                        * value_lo.clone(),
                ),
                (
                    "calldata_value_hi",
                    q_enable.clone() * calldata_condition.clone() * value_hi.clone(),
                ),
                (
                    "calldata_pointer_hi",
                    q_enable.clone() * calldata_condition * pointer_hi.clone(),
                ),
                //1. first_access=1 => is_write=1
                //2. value_hi=0
                //3. pointer_hi=0
                (
                    "returndata_first_access_write",
                    q_enable.clone()
                        * return_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "returndata_value_hi",
                    q_enable.clone() * return_condition.clone() * value_hi.clone(),
                ),
                (
                    "returndata_pointer_hi",
                    q_enable.clone() * return_condition * pointer_hi,
                ),
            ];

            let mut index_is_stamp_expr = 0.expr();
            for tag in [LimbIndex::Stamp0, LimbIndex::Stamp1] {
                index_is_stamp_expr = index_is_stamp_expr.clone()
                    + config
                        .ordering_config
                        .first_different_limb
                        .value_equals(tag, Rotation::cur())(meta);
            }
            // 1 - is_first_access === index = Stamp0 | Stamp1
            vec.push((
                "1 - is_first_access === index = Stamp0 | Stamp1",
                q_enable.clone()
                    * (index_is_stamp_expr.clone() + is_first_access.clone() - 1.expr()),
            ));
            vec.push((
                "is_first_access=0 & is_write=0 ==> prev_value_lo=cur_value_lo",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * (prev_value_lo - value_lo)
                    * (1.expr() - is_write.clone()),
            ));
            vec.push((
                "is_first_access=0 & is_write=0 ==> prev_value_hi=cur_value_hi",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * (prev_value_hi - value_hi)
                    * (1.expr() - is_write.clone()),
            ));
            vec
        });

        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any("STATE_lookup_stack_pointer", |meta| {
            let mut constraints = vec![];

            // 1<= pointer_lo <=1024 in stack
            let entry = LookupEntry::U10(meta.query_advice(config.pointer_lo, Rotation::cur()));
            let stack_condition = config.tag.value_equals(state::Tag::Stack, Rotation::cur())(meta);
            if let LookupEntry::Conditional(expr, entry) = entry.conditional(stack_condition) {
                let lookup_vec = config.fixed_table.get_lookup_vector(meta, *entry);
                constraints = lookup_vec
                    .into_iter()
                    .map(|(left, right)| {
                        let q_enable = meta.query_selector(config.q_enable);
                        (q_enable * left * expr.clone(), right)
                    })
                    .collect();
            }
            constraints
        });
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any("STATE_lookup_memory_pointer", |meta| {
            let mut constraints = vec![];
            // 0<= value_lo < 256 in memory
            let entry = LookupEntry::U8(meta.query_advice(config.value_lo, Rotation::cur()));
            let memory_condition =
                config.tag.value_equals(state::Tag::Memory, Rotation::cur())(meta);
            if let LookupEntry::Conditional(expr, entry) = entry.conditional(memory_condition) {
                let lookup_vec = config.fixed_table.get_lookup_vector(meta, *entry);
                constraints = lookup_vec
                    .into_iter()
                    .map(|(left, right)| {
                        let q_enable = meta.query_selector(config.q_enable);
                        (q_enable * left * expr.clone(), right)
                    })
                    .collect();
            }
            constraints
        });

        config
    }
}

impl<F: Field> StateCircuitConfig<F> {
    /// Padding assignment on rows with no data, and fill most columns with 0.
    /// Only first_different_limb and tag columns are assigned the specified value,
    /// EndPadding indicates the tag of padding in this column.
    /// If the value of first_different_limb is Stamp0|Stamp1, the first_access
    /// constraint logics is not enabled.
    fn assign_padding_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        assign_advice_or_fixed(region, offset, &U256::zero(), self.stamp)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.value_hi)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.value_lo)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.pointer_hi)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.pointer_lo)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.call_id_contract_addr)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.is_first_access)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.is_write)?;
        let tag = BinaryNumberChip::construct(self.tag);
        tag.assign(region, offset, &Tag::EndPadding)?;

        self.sort_keys
            .call_id_or_address
            .assign(region, offset, U256::zero())?;
        self.sort_keys
            .pointer_hi
            .assign(region, offset, U256::zero())?;
        self.sort_keys
            .pointer_lo
            .assign(region, offset, U256::zero())?;
        self.sort_keys.stamp.assign(region, offset, 0)?;
        let first_different_limb =
            BinaryNumberChip::construct(self.ordering_config.first_different_limb);
        first_different_limb.assign(region, offset, &LimbIndex::Stamp0)?;
        assign_advice_or_fixed(
            region,
            offset,
            &U256::zero(),
            self.ordering_config.limb_difference,
        )?;
        assign_advice_or_fixed(
            region,
            offset,
            &U256::zero(),
            self.ordering_config.limb_difference_inverse,
        )?;

        Ok(())
    }

    #[rustfmt::skip]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let tag = BinaryNumberChip::construct(self.tag);
        tag.assign(region, offset, &row.tag.unwrap_or_default())?;
        assign_advice_or_fixed(region, offset, &row.stamp.unwrap_or_default(), self.stamp)?;
        assign_advice_or_fixed(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
        assign_advice_or_fixed(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
        assign_advice_or_fixed(region, offset, &row.call_id_contract_addr.unwrap_or_default(), self.call_id_contract_addr)?;
        assign_advice_or_fixed(region, offset, &row.pointer_hi.unwrap_or_default(), self.pointer_hi)?;
        assign_advice_or_fixed(region, offset, &row.pointer_lo.unwrap_or_default(), self.pointer_lo)?;
        assign_advice_or_fixed(region, offset, &row.is_write.unwrap_or_default(), self.is_write)?;
        // Assign value to the column of elements to be sorted
        self.sort_keys
            .call_id_or_address
            .assign(region, offset, row.call_id_contract_addr.unwrap_or_default())?;
        self.sort_keys
            .pointer_hi
            .assign(region, offset, row.pointer_hi.unwrap_or_default())?;
        self.sort_keys
            .pointer_lo
            .assign(region, offset, row.pointer_lo.unwrap_or_default())?;
        self.sort_keys
            .stamp
            .assign(region, offset, row.stamp.unwrap_or_default().as_u32())?;
        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // Assign data of the status to circuit row with row offset
        for (offset, row) in witness.state.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }
        // pad the rest rows
        for offset in witness.state.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset)?;
        }
        // 1. assign ordering with curr and prev state.
        // 2. if and only if the difference with two status not in Stamp*,
        // indicates that the location by the pointer is accessed for the first time,
        for (i, state) in witness.state.iter().enumerate() {
            if i > 0 {
                let prev_row = &witness.state[i - 1];
                let index = self.ordering_config.assign(region, i, state, prev_row)?;
                let is_first_access = !matches!(index, LimbIndex::Stamp0 | LimbIndex::Stamp1);
                // If the location by pointer is accessed for the first time, set the
                // is_first_access column of the current row to 1, otherwise it is 0.
                #[rustfmt::skip]
                assign_advice_or_fixed(
                    region,
                    i,
                    &U256::from(if is_first_access { 1 } else { 0 }),
                    self.is_first_access,
                )?;
            }
        }

        Ok(())
    }

    /// Annotate and name columns
    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "STATE_value_hi", self.value_hi);
        region.name_column(|| "STATE_value_lo", self.value_lo);
        region.name_column(|| "STATE_stamp", self.stamp);
        region.name_column(|| "STATE_call_id_contract_addr", self.call_id_contract_addr);
        region.name_column(|| "STATE_pointer_hi", self.pointer_hi);
        region.name_column(|| "STATE_pointer_lo", self.pointer_lo);
        region.name_column(|| "STATE_is_write", self.is_write);
        self.tag
            .annotate_columns_in_region(region, "STATE_config_tag");
        self.sort_keys
            .tag
            .annotate_columns_in_region(region, "STATE_sort_elements_tag");
        self.sort_keys
            .call_id_or_address
            .annotate_columns_in_region(region, "STATE_sore_elements_call_id_or_address");
        self.sort_keys
            .pointer_hi
            .annotate_columns_in_region(region, "STATE_sore_elements_pointer_hi");
        self.sort_keys
            .pointer_lo
            .annotate_columns_in_region(region, "STATE_sore_elements_pointer_lo");
        self.sort_keys
            .stamp
            .annotate_colums_in_region(region, "STATE_sore_elements_stamp");
        self.ordering_config
            .annotate_columns_in_region(region, "STATE_ordering");
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
        layouter: &mut impl Layouter<F>,
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
    use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::bytecode;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct StateTestCircuitConfig<F: Field> {
        pub state_circuit: StateCircuitConfig<F>,
        pub fixed_circuit: FixedCircuitConfig<F>,
    }

    #[derive(Clone, Default, Debug)]
    pub struct StateTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        state_circuit: StateCircuit<F, MAX_NUM_ROW>,
        fixed_circuit: FixedCircuit<F>,
    }

    impl<F: Field> SubCircuitConfig<F> for StateTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            let q_enable: Selector = meta.complex_selector(); //todo complex?
            let state_table = StateTable::construct(meta, q_enable);
            let fixed_table = FixedTable::construct(meta);
            StateTestCircuitConfig {
                state_circuit: StateCircuitConfig::new(
                    meta,
                    StateCircuitConfigArgs {
                        q_enable,
                        state_table,
                        fixed_table,
                    },
                ),
                fixed_circuit: FixedCircuitConfig::new(
                    meta,
                    FixedCircuitConfigArgs { fixed_table },
                ),
            }
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for StateTestCircuit<F, MAX_NUM_ROW> {
        type Config = StateTestCircuitConfig<F>;
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
            self.state_circuit
                .synthesize_sub(&config.state_circuit, &mut layouter)?;
            // when feature `no_fixed_lookup` is on, we don't do synthesize
            #[cfg(not(feature = "no_fixed_lookup"))]
            self.fixed_circuit
                .synthesize_sub(&config.fixed_circuit, &mut layouter)?;
            Ok(())
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> StateTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness) -> Self {
            Self {
                state_circuit: StateCircuit::new_from_witness(&witness),
                fixed_circuit: FixedCircuit::new_from_witness(&witness),
            }
        }
    }

    fn test_state_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        println!("K: {}", k);
        let circuit = StateTestCircuit::<Fp, MAX_NUM_ROW>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[test]
    fn test_state_parser() {
        let bytecode = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            ADD
        };
        let trace = trace_parser::trace_program(bytecode.to_vec().as_slice(), &[]);
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            bytecode.to_vec().as_slice(),
            &[],
            false,
            Default::default(),
        ));
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_valid_ordering_state() {
        let witness = Witness {
            state: vec![
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(8.into()),
                    stamp: Some(10.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(9.into()),
                    stamp: Some(11.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }

    // when feature `no_fixed_lookup` is on, we skip the test
    // this is due to the test relies on lookup the `limb_difference` value in range U16
    #[cfg_attr(
        feature = "no_fixed_lookup",
        ignore = "feature `no_fixed_lookup` is on, we skip the test"
    )]
    #[test]
    fn test_invalid_order() {
        let witness = Witness {
            state: vec![
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(9.into()),
                    stamp: Some(10.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(8.into()),
                    stamp: Some(11.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let prover = test_state_circuit(witness);
        match prover.verify_par() {
            Ok(()) => panic!("should be error"),
            Err(errs) => println!("{:?}", errs),
        };
    }
}
