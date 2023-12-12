use crate::constant::LOG_NUM_BITWISE_TAG;
use crate::table::{FixedTable, LookupEntry};

use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::bitwise::Row;
use crate::witness::Witness;
use eth_types::Field;

use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::circuit::{Layouter, Region, Value};

use crate::witness::bitwise::Tag;
use gadgets::is_zero::IsZeroInstruction;
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Number of operands in one row
pub(crate) const NUM_OPERAND: usize = 3;

#[derive(Clone)]
pub struct BitwiseCircuitConfig<F: Field> {
    q_enable: Selector,
    /// The operation tag, one of AND, OR, XOR
    pub tag: BinaryNumberConfig<Tag, LOG_NUM_BITWISE_TAG>,
    /// The byte values of operands in one row
    pub bytes: [Column<Advice>; NUM_OPERAND],
    /// The accumulation of bytes in one operation for each operand in one row
    pub acc_vec: [Column<Advice>; NUM_OPERAND],
    /// The sum of bytes in one operation of operand 2, used to compute byte opcode
    pub sum_2: Column<Advice>,
    /// The counter for one operation
    pub cnt: Column<Advice>,
    /// IsZero chip for column cnt
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
    // table used for lookup
    fixed_table: FixedTable,
}

pub struct BitwiseCircuitConfigArgs {
    pub fixed_table: FixedTable,
}

impl<F: Field> SubCircuitConfig<F> for BitwiseCircuitConfig<F> {
    type ConfigArgs = BitwiseCircuitConfigArgs;
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { fixed_table }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let bytes: [Column<Advice>; NUM_OPERAND] = std::array::from_fn(|_| meta.advice_column());
        let acc_vec: [Column<Advice>; NUM_OPERAND] = std::array::from_fn(|_| meta.advice_column());
        let sum_2 = meta.advice_column();
        let cnt = meta.advice_column();
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let config = Self {
            q_enable,
            tag,
            bytes,
            acc_vec,
            sum_2,
            cnt,
            cnt_is_zero,
            fixed_table,
        };

        meta.create_gate("BITWISE", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let tag = config.tag.value(Rotation::cur())(meta);
            let byte_0 = meta.query_advice(config.bytes[0], Rotation::cur());
            let byte_1 = meta.query_advice(config.bytes[1], Rotation::cur());
            let byte_2 = meta.query_advice(config.bytes[2], Rotation::cur());
            let acc_0 = meta.query_advice(config.acc_vec[0], Rotation::cur());
            let acc_1 = meta.query_advice(config.acc_vec[1], Rotation::cur());
            let acc_2 = meta.query_advice(config.acc_vec[2], Rotation::cur());
            let sum_2 = meta.query_advice(config.sum_2, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let tag_is_nil = config.tag.value_equals(Tag::Nil, Rotation::cur())(meta);

            let tag_prev = config.tag.value(Rotation::prev())(meta);
            let acc_0_prev = meta.query_advice(config.acc_vec[0], Rotation::prev());
            let acc_1_prev = meta.query_advice(config.acc_vec[1], Rotation::prev());
            let acc_2_prev = meta.query_advice(config.acc_vec[2], Rotation::prev());
            let sum2_prev = meta.query_advice(config.sum_2, Rotation::prev());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            let cnt_next_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::next());

            // tag_is_not_nil, cnt=0 ---> acc_0=byte_0、acc_1=byte_1、acc_2=byte_2、sum_2=byte_2
            let tag_is_not_nil = q_enable.clone() * (1.expr() - tag_is_nil.clone());
            let mut constraints = vec![
                (
                    "tag_is_not_nil, cnt=0 => acc_0=byte_0",
                    tag_is_not_nil.clone() * cnt_is_zero.clone() * (byte_0.clone() - acc_0.clone()),
                ),
                (
                    "tag_is_not_nil, cnt=0 => acc_1=byte_1",
                    tag_is_not_nil.clone() * cnt_is_zero.clone() * (byte_1.clone() - acc_1.clone()),
                ),
                (
                    "tag_is_not_nil, cnt=0 => acc_2=byte_2",
                    tag_is_not_nil.clone() * cnt_is_zero.clone() * (byte_2.clone() - acc_2.clone()),
                ),
                (
                    "tag_is_not_nil, cnt=0 => sum_2=byte_2",
                    tag_is_not_nil.clone() * cnt_is_zero.clone() * (byte_2.clone() - sum_2.clone()),
                ),
            ];

            // tag_is_not_nil, cnt != 0 ---> acc_0=byte_0+acc_0_pre*256，acc_1=byte_1+acc_1_pre*256，acc_2=acc_2_pre*256, sum_2=byte_2+sum2_pre，tag=tag_pre
            let cnt_is_not_zero = 1.expr() - cnt_is_zero.clone();
            constraints.extend(vec![
                (
                    "tag_is_not_nil, cnt!=0 => acc_0=byte_0+acc_0_pre*256",
                    tag_is_not_nil.clone()
                        * cnt_is_not_zero.clone()
                        * (acc_0.clone() - (byte_0.clone() + acc_0_prev * 256.expr())),
                ),
                (
                    "tag_is_not_nil, cnt!=0 => acc_1=byte_1+acc_1_pre*256",
                    tag_is_not_nil.clone()
                        * cnt_is_not_zero.clone()
                        * (acc_1.clone() - (byte_1.clone() + acc_1_prev * 256.expr())),
                ),
                (
                    "tag_is_not_nil, cnt!=0 => acc_2=byte_2+acc_2_pre*256",
                    tag_is_not_nil.clone()
                        * cnt_is_not_zero.clone()
                        * (acc_2.clone() - (byte_2.clone() + acc_2_prev * 256.expr())),
                ),
                (
                    "tag_is_not_nil, cnt!=0 => sum2=byte_2+sum_2_pre",
                    tag_is_not_nil.clone()
                        * cnt_is_not_zero.clone()
                        * (sum_2.clone() - (byte_2.clone() + sum2_prev)),
                ),
                (
                    "tag_is_not_nil, cnt!=0 => cnt=cnt_prev+1",
                    tag_is_not_nil.clone()
                        * cnt_is_not_zero.clone()
                        * (cnt.clone() - (cnt_prev + 1.expr())),
                ),
                (
                    "tag_is_not_nil, cnt!=0 => tag=tag+tag_prev",
                    tag_is_not_nil.clone() * cnt_is_not_zero.clone() * (tag - tag_prev),
                ),
            ]);

            // tag_is_not_nil，next_cnt=0 --> cnt=15
            constraints.extend(vec![(
                "tag_is_not_nil, next_cnt=0 => cnt=15",
                tag_is_not_nil.clone() * cnt_next_is_zero.clone() * (cnt.clone() - 15.expr()),
            )]);

            // tag_is_nil --> byte_0=0, byte_1=0, byte_2=0, acc_0=0, acc_1=0, acc_2=0, sum_2=0, cnt=0
            let tag_is_nil = q_enable.clone() * tag_is_nil;
            constraints.extend(vec![
                ("tag_is_nil => byte_0=0", tag_is_nil.clone() * byte_0),
                ("tag_is_nil => byte_1=0", tag_is_nil.clone() * byte_1),
                ("tag_is_nil => byte_2=0", tag_is_nil.clone() * byte_2),
                ("tag_is_nil => acc_0=0", tag_is_nil.clone() * acc_0),
                ("tag_is_nil => acc_1=0", tag_is_nil.clone() * acc_1),
                ("tag_is_nil => acc_2=0", tag_is_nil.clone() * acc_2),
                ("tag_is_nil => sum_2=0", tag_is_nil.clone() * sum_2),
                ("tag_is_nil => cnt=0", tag_is_nil.clone() * cnt),
            ]);
            constraints
        });

        // lookup constraint
        //config.fixed_lookup(meta, "BITWISE_LOOKUP");

        config
    }
}

impl<F: Field> BitwiseCircuitConfig<F> {
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let tag: BinaryNumberChip<F, Tag, LOG_NUM_BITWISE_TAG> =
            BinaryNumberChip::construct(self.tag);
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());

        tag.assign(region, offset, &row.tag)?;
        assign_advice_or_fixed(region, offset, &row.byte_0, self.bytes[0])?;
        assign_advice_or_fixed(region, offset, &row.byte_1, self.bytes[1])?;
        assign_advice_or_fixed(region, offset, &row.byte_2, self.bytes[2])?;
        assign_advice_or_fixed(region, offset, &row.acc_0, self.acc_vec[0])?;
        assign_advice_or_fixed(region, offset, &row.acc_1, self.acc_vec[1])?;
        assign_advice_or_fixed(region, offset, &row.acc_2, self.acc_vec[2])?;
        assign_advice_or_fixed(region, offset, &row.sum_2, self.sum_2)?;
        assign_advice_or_fixed(region, offset, &row.cnt, self.cnt)?;

        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt))),
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
        // assign the rest rows
        for (offset, row) in witness.bitwise.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }

        // pad the rest rows
        for offset in witness.bitwise.len()..num_row_incl_padding {
            self.assign_row(region, offset, &Default::default())?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        self.tag.annotate_columns_in_region(region, "BITWISE_tag");
        region.name_column(|| "BITWISE_byte0", self.bytes[0]);
        region.name_column(|| "BITWISE_byte1", self.bytes[1]);
        region.name_column(|| "BITWISE_byte2", self.bytes[2]);
        region.name_column(|| "BITWISE_acc0", self.acc_vec[0]);
        region.name_column(|| "BITWISE_acc1", self.acc_vec[1]);
        region.name_column(|| "BITWISE_acc2", self.acc_vec[2]);
        region.name_column(|| "BITWISE_sum2", self.sum_2);
        region.name_column(|| "BITWISE_cnt", self.cnt);
    }

    /// lookup target: fixed table
    pub fn fixed_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        meta.lookup_any(name, |meta| {
            let fixed_entry = LookupEntry::Fixed {
                tag: self.tag.value(Rotation::cur())(meta),
                values: [
                    meta.query_advice(self.bytes[0], Rotation::cur()),
                    meta.query_advice(self.bytes[1], Rotation::cur()),
                    meta.query_advice(self.bytes[2], Rotation::cur()),
                ],
            };

            let fixed_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .fixed_table
                .get_lookup_vector(meta, fixed_entry.clone());

            fixed_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let tag_is_nil = self.tag.value_equals(Tag::Nil, Rotation::cur())(meta);
                    (q_enable * (1.expr() - tag_is_nil) * left, right)
                })
                .collect()
        });
    }
}

#[derive(Clone, Default, Debug)]
pub struct BitwiseCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for BitwiseCircuit<F, MAX_NUM_ROW> {
    type Config = BitwiseCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        BitwiseCircuit {
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
            || "bitwise circuit",
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
        (1, 1)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.bitwise.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::util::{convert_f_to_u256, convert_u256_to_f, geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::U256;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::{Fr as Fp, Fr};
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct CopyTestCircuitConfig<F: Field> {
        pub bitwise_circuit: BitwiseCircuitConfig<F>,
    }

    impl<F: Field> SubCircuitConfig<F> for CopyTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
            let q_enable_bytecode = meta.complex_selector();
            let q_enable_state = meta.complex_selector();
            let fixed_table = FixedTable::construct(meta);
            let bitwise_circuit =
                BitwiseCircuitConfig::new(meta, BitwiseCircuitConfigArgs { fixed_table });
            CopyTestCircuitConfig { bitwise_circuit }
        }
    }

    #[derive(Clone, Default, Debug)]
    pub struct BitwiseTestCircuit<F: Field, const MAX_CODESIZE: usize> {
        pub bitwise_circuit: BitwiseCircuit<F, MAX_CODESIZE>,
    }

    impl<F: Field, const MAX_CODESIZE: usize> Circuit<F> for BitwiseTestCircuit<F, MAX_CODESIZE> {
        type Config = CopyTestCircuitConfig<F>;
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
            self.bitwise_circuit
                .synthesize_sub(&config.bitwise_circuit, &mut layouter)
        }
    }

    impl<F: Field, const MAX_CODESIZE: usize> BitwiseTestCircuit<F, MAX_CODESIZE> {
        pub fn new(witness: Witness) -> Self {
            Self {
                bitwise_circuit: BitwiseCircuit::new_from_witness(&witness),
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bitwise_circuit.instance());
            vec
        }
    }

    fn test_simple_bitwise_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = BitwiseTestCircuit::<Fp, MAX_NUM_ROW>::new(witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_core_parser() {
        // STOP
        let bytes = hex::decode("00").unwrap();
        let machine_code = Vec::from(bytes);
        let trace = trace_parser::trace_program(&machine_code);
        let mut witness: Witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        let calc_len = 16;
        // generate data
        let mut num_1: Vec<u8> = vec![0xabu8, 0xcdu8, 0xefu8];
        let mut num_2: Vec<u8> = vec![0xaau8, 0xbbu8, 0xccu8];

        for i in num_1.len()..calc_len {
            num_1.push(0x00u8)
        }

        for i in num_2.len()..calc_len {
            num_2.push(0x00u8)
        }

        // generate bitwise row
        witness.bitwise = vec![];
        (0..BitwiseCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| witness.bitwise.insert(0, Default::default()));

        // begin padding
        let mut byte_acc_pre_vec = vec![U256::from(0), U256::from(0), U256::from(0)];
        let mut byte_2_sum_pre = U256::from(0);

        let temp_256_f = Fr::from(256);

        for i in 0..calc_len {
            let byte_vec = vec![
                U256::from(num_1[i]),
                U256::from(num_2[i]),
                U256::from(num_1[i] & num_2[i]),
            ];

            let mut byte_acc_vec: Vec<U256> = vec![];
            let mut byte_2_sum = U256::from(0);

            for i in 0..3 {
                let mut acc_f = convert_u256_to_f::<Fr>(&byte_acc_pre_vec[i]);
                let byte_f = convert_u256_to_f::<Fr>(&byte_vec[i]);
                acc_f = byte_f + acc_f * temp_256_f;
                byte_acc_vec.push(convert_f_to_u256(&acc_f));
                byte_acc_pre_vec[i] = byte_acc_vec[i];

                // calc byte_2_sum
                if i == 2 {
                    let mut byte_2_sum_f = convert_u256_to_f::<Fr>(&byte_2_sum_pre);
                    byte_2_sum_f = byte_f + byte_2_sum_f;
                    byte_2_sum = convert_f_to_u256(&byte_2_sum_f);
                    byte_2_sum_pre = byte_2_sum;
                }
            }

            let row = Row {
                tag: Tag::And,
                byte_0: byte_vec[0],
                byte_1: byte_vec[1],
                byte_2: byte_vec[2],
                acc_0: byte_acc_vec[0],
                acc_1: byte_acc_vec[1],
                acc_2: byte_acc_vec[2],
                sum_2: byte_2_sum,
                cnt: U256::from(i),
            };
            witness.bitwise.push(row);
        }
        let prover = test_simple_bitwise_circuit(witness);
        prover.assert_satisfied_par();
    }
}
