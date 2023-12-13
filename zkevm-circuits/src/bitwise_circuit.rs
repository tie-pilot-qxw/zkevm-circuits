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
    use crate::constant::MAX_CODESIZE;
    use crate::util::{convert_u256_to_16_bytes, geth_data_test, log2_ceil};
    use crate::witness::{bitwise, Witness};
    use eth_types::U256;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::{Fr as Fp, Fr};
    use halo2_proofs::plonk::Circuit;
    use serde::Serialize;
    use std::fs::File;

    #[derive(Clone, Debug, Default, Serialize)]
    pub struct BitwiseTestRow {
        pub tag: Tag,
        pub acc_0: U256,
        pub acc_1: U256,
        pub acc_2: U256,
        pub sum_2: U256,
    }

    #[derive(Clone)]
    pub struct BitwiseTestCircuitConfig<F: Field> {
        q_enable: Selector,
        pub bitwise_circuit: BitwiseCircuitConfig<F>,
        pub tag: Column<Advice>,
        pub acc_0: Column<Advice>,
        pub acc_1: Column<Advice>,
        pub acc_2: Column<Advice>,
        pub sum_2: Column<Advice>,
    }

    impl<F: Field> SubCircuitConfig<F> for BitwiseTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
            let q_enable = meta.complex_selector();
            let fixed_table = FixedTable::construct(meta);
            let bitwise_circuit =
                BitwiseCircuitConfig::new(meta, BitwiseCircuitConfigArgs { fixed_table });
            BitwiseTestCircuitConfig {
                q_enable,
                bitwise_circuit,
                tag: meta.advice_column(),
                acc_0: meta.advice_column(),
                acc_1: meta.advice_column(),
                acc_2: meta.advice_column(),
                sum_2: meta.advice_column(),
            }
        }
    }
    impl<F: Field> BitwiseTestCircuitConfig<F> {
        pub fn assign_with_region(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &BitwiseTestRow,
        ) -> Result<(), Error> {
            assign_advice_or_fixed(region, offset, &U256::from(row.tag as usize), self.tag)?;
            assign_advice_or_fixed(region, offset, &row.acc_0, self.acc_0)?;
            assign_advice_or_fixed(region, offset, &row.acc_1, self.acc_1)?;
            assign_advice_or_fixed(region, offset, &row.acc_2, self.acc_2)?;
            assign_advice_or_fixed(region, offset, &row.sum_2, self.sum_2)?;
            Ok(())
        }
    }
    #[derive(Clone, Default, Debug)]
    pub struct BitwiseTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub bitwise_circuit: BitwiseCircuit<F, MAX_NUM_ROW>,
        pub rows: Vec<BitwiseTestRow>,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for BitwiseTestCircuit<F, MAX_NUM_ROW> {
        type Config = BitwiseTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let config = Self::Config::new(meta, ());

            meta.lookup_any("bitwise test lookup", |meta| {
                let bitwise_entry_tag = meta.query_advice(config.tag, Rotation::cur());
                let bitwise_entry_acc_0 = meta.query_advice(config.acc_0, Rotation::cur());
                let bitwise_entry_acc_1 = meta.query_advice(config.acc_1, Rotation::cur());
                let bitwise_entry_acc_2 = meta.query_advice(config.acc_2, Rotation::cur());
                let bitwise_entry_sum_2 = meta.query_advice(config.sum_2, Rotation::cur());

                let bitwise_circuit_tag = config.bitwise_circuit.tag.value(Rotation::cur())(meta);
                let bitwise_circuit_acc_0 =
                    meta.query_advice(config.bitwise_circuit.acc_vec[0], Rotation::cur());
                let bitwise_circuit_acc_1 =
                    meta.query_advice(config.bitwise_circuit.acc_vec[1], Rotation::cur());
                let bitwise_circuit_acc_2 =
                    meta.query_advice(config.bitwise_circuit.acc_vec[2], Rotation::cur());
                let bitwise_circuit_sum2 =
                    meta.query_advice(config.bitwise_circuit.sum_2, Rotation::cur());

                let q_enable = meta.query_selector(config.q_enable);

                vec![
                    (bitwise_entry_tag, bitwise_circuit_tag),
                    (
                        q_enable.clone() * bitwise_entry_acc_0,
                        bitwise_circuit_acc_0,
                    ),
                    (
                        q_enable.clone() * bitwise_entry_acc_1,
                        bitwise_circuit_acc_1,
                    ),
                    (
                        q_enable.clone() * bitwise_entry_acc_2,
                        bitwise_circuit_acc_2,
                    ),
                    (q_enable * bitwise_entry_sum_2, bitwise_circuit_sum2),
                ]
            });

            config
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.bitwise_circuit
                .synthesize_sub(&config.bitwise_circuit, &mut layouter)?;

            layouter.assign_region(
                || "bitwise circuit test",
                |mut region| {
                    for (offset, row) in self.rows.iter().enumerate() {
                        config.q_enable.enable(&mut region, offset)?;
                        config.assign_with_region(&mut region, offset, row)?;
                    }
                    Ok(())
                },
            )
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> BitwiseTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness, rows: Vec<BitwiseTestRow>) -> Self {
            Self {
                bitwise_circuit: BitwiseCircuit::new_from_witness(&witness),
                rows,
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bitwise_circuit.instance());
            vec
        }
    }

    fn test_simple_bitwise_circuit<F: Field>(
        witness: Witness,
        rows: Vec<BitwiseTestRow>,
    ) -> MockProver<Fp> {
        let k = log2_ceil(MAX_CODESIZE);
        let mut circuit = BitwiseTestCircuit::<Fp, MAX_CODESIZE>::new(witness, rows);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover
    }

    fn test_bitwise_circuit_lookup(
        tag: Tag,
        op1: u128,
        op2: u128,
        lookup_expect_acc_row: BitwiseTestRow,
    ) {
        // STOP
        let bytes = hex::decode("64123456789a601f1a00").unwrap();
        let machine_code = Vec::from(bytes);
        let trace = trace_parser::trace_program(&machine_code);
        let mut witness: Witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        // generate bitwise row
        witness.bitwise = vec![];
        (0..BitwiseCircuit::<Fr, MAX_CODESIZE>::unusable_rows().0)
            .for_each(|_| witness.bitwise.insert(0, Default::default()));

        let operand1 = U256::from(op1); // 0x123456789a
        let operand2 = U256::from(op2); // 0xff

        let operand1_hi = (operand1 >> 128).as_u128();
        let operand1_low = operand1.low_u128();

        let operand2_hi = (operand2 >> 128).as_u128();
        let operand2_low = operand2.low_u128();

        // get bitwise rows
        let bitwise_low_rows = bitwise::get_bitwise_row::<Fp>(Tag::And, operand1_low, operand2_low);
        let bitwise_hi_rows = bitwise::get_bitwise_row::<Fp>(Tag::And, operand1_hi, operand2_hi);

        for row in bitwise_low_rows.clone() {
            println!("tag:{:?}, byte_0:{:?}, byte_1:{:?}, byte_2:{:?}, acc_0:{:?}, acc_1:{:?}, acc_2:{:?}, sum2:{:?}, cnt:{:?}",
                     row.tag,
                     hex::encode(convert_u256_to_16_bytes(&row.byte_0)),
                     hex::encode(convert_u256_to_16_bytes(&row.byte_1)),
                     hex::encode(convert_u256_to_16_bytes(&row.byte_2)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_0)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_1)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_2)),
                     hex::encode(convert_u256_to_16_bytes(&row.sum_2)),
                     row.cnt
            );
        }

        println!();
        for row in bitwise_hi_rows.clone() {
            println!("tag:{:?}, byte_0:{:?}, byte_1:{:?}, byte_2:{:?}, acc_0:{:?}, acc_1:{:?}, acc_2:{:?}, sum2:{:?}, cnt:{:?}",
                     row.tag,
                     hex::encode(convert_u256_to_16_bytes(&row.byte_0)),
                     hex::encode(convert_u256_to_16_bytes(&row.byte_1)),
                     hex::encode(convert_u256_to_16_bytes(&row.byte_2)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_0)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_1)),
                     hex::encode(convert_u256_to_16_bytes(&row.acc_2)),
                     hex::encode(convert_u256_to_16_bytes(&row.sum_2)),
                     row.cnt
            );
        }

        witness.bitwise.extend(bitwise_low_rows);
        witness.bitwise.extend(bitwise_hi_rows);

        // generate bitwise test row
        let bitwise_test_rows = vec![lookup_expect_acc_row];

        let mut buf = std::io::BufWriter::new(File::create("demo.html").unwrap());
        witness.write_html(&mut buf);
        witness.print_csv();
        let prover = test_simple_bitwise_circuit::<Fp>(witness, bitwise_test_rows);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_bitwise_acc_lookup1() {
        let operand1 = 0x123456789a_u128; // 0x123456789a
        let operand2 = 0xff_u128; // 0xff

        let lookup_expect_acc_row = BitwiseTestRow {
            tag: Tag::And,
            acc_0: U256::from(0x123456789a_u128), // 0x123456789a,
            acc_1: U256::from(0xff_u128),         // 0xff
            acc_2: U256::from(0x123456789a_u128 & 0xff_u128), // 0x9a
            sum_2: U256::from(0x9a_u128),         // 0x9a
        };

        test_bitwise_circuit_lookup(Tag::And, operand1, operand2, lookup_expect_acc_row)
    }

    #[test]
    fn test_bitwise_acc_lookup2() {
        let operand1 = 0xabcdef_u128; // 0x123456789a
        let operand2 = 0xaabbcc_u128; // 0xff

        let lookup_expect_acc_row = BitwiseTestRow {
            tag: Tag::And,
            acc_0: U256::from(0xabcdef_u128), // 0xabcdef,
            acc_1: U256::from(0xaabbcc_u128), // 0xaabbcc
            acc_2: U256::from(0xaa89cc_u128), // 0xaa89cc
            sum_2: U256::from(0x01ff_u128),   // 0x01ff
        };

        test_bitwise_circuit_lookup(Tag::And, operand1, operand2, lookup_expect_acc_row)
    }
}
