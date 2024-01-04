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

/// Overview:
///  a circuit that specifically handles bitwise operations such as AND OR XOR BYTE。
///  in this circuit, integers are broken into bytes and logical operations are performed on bytes.
///
/// Table layout
/// +---+--------+--------+--------+---------+------+-------+-------+-------+
/// |tag| byte_0 | byte_1 | byte_2 |  acc_0 | acc_1 | acc_2 | sum_2 |  cnt  |
/// +---+--------+--------+--------+-------+--------+-------+-------+-------+
/// tag: Nil、And、Or、Xor (Nil is the default value)
/// byte_0: operand1
/// byte_1: operand2
/// byte_2: calc result(And: operand1 & operand2、Or: operand1 | operand2, Xor: operand1 ^ operand2)
/// acc_0: accumulated value of byte_0, `acc_0=byte_0+acc_0_pre*256`
/// acc_1: accumulated value of byte_1, `acc_1=byte_1+acc_1_pre*256`
/// acc_2: accumulated value of byte_2, `acc_2=acc_2_pre*256`
/// sum_2: cumulative sum of byte_2, `sum_2=byte_2+sum2_pre`
/// cnt: counter, ranging from 0 to 15
///
/// Example:
///  0xabcdef AND 0xaabbcc
///  | tag  | byte_0 | byte_1 | byte_2 | acc_0    | acc_1    | acc_2    | sum_2 | cnt  |
///  | ---- | ------ | ------ | ------ | -------- | -------- | -------- | ----- | ---- |
///  | And  | 0xab   | 0xaa   | 0xaa   | 0xab     | 0xaa     | 0xaa     | 0xaa  | 0    |
///  | And  | 0xcd   | 0xbb   | 0x89   | 0xabcd   | 0xaabb   | 0xaa89   | 0x133 | 1    |
///  | And  | 0xef   | 0xcc   | 0xcc   | 0xabcdef | 0xaabbcc | 0xaa89cc | 0x1ff | 2    |
///
/// note: in actual operation, the integer participating in the operation will be divided into 16 bytes, if the length
///       after division is not 16 bytes, 0 will be added.
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

    /// Constructor， used to construct config object
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { fixed_table }: Self::ConfigArgs,
    ) -> Self {
        // initialize columns
        let q_enable = meta.complex_selector();
        let tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let bytes: [Column<Advice>; NUM_OPERAND] = std::array::from_fn(|_| meta.advice_column());
        let acc_vec: [Column<Advice>; NUM_OPERAND] = std::array::from_fn(|_| meta.advice_column());
        let sum_2 = meta.advice_column();
        let cnt = meta.advice_column();
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        // construct config object
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

        // Bitwise gate constraints
        //  the default tag of Nil. Currently, the rows with Nil tag are rows without actual data, they exist to make up the number of table rows, that is, padding rows.
        //  all values in rows with tag Nil should be default values, that is, byte_0, byte_1, byte_2, acc_0, acc_1,acc_2, sum_2=0, cnt are all 0.
        // if the tage of the current row is not Nil, there are the following constraints:
        // 1) each operation is based on a group of 16 bytes, that is, the range of cnt value is 0~15，if cnt_next=0, then cnt_cur must be 15
        // 2）the row with cnt 0 is the first row of an operation, acc_0=byte_0、acc_1=byte_1、acc_2=byte_2、sum_2=byte_2
        // 3) if cnt is not equal to 0, the values of acc_0, acc_1, acc_2, and sum2 need to be calculated:
        //    acc_0=byte_0+acc_0_pre*256
        //    acc_1=byte_1+acc_1_pre*25
        //    acc_2=acc_2_pre*256
        //    sum_2=byte_2+sum2_pre
        // 4) if cnt is not equal to 0, the tag of the current row should be equal to the tag of the previous row,
        //    because it is in the same calculation.
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

            // tag_is_not_nil, cnt != 0 --->
            //    tag=tag_pre
            //    acc_0=byte_0+acc_0_pre*256
            //    acc_1=byte_1+acc_1_pre*256
            //    acc_2=acc_2_pre*256
            //    sum_2=byte_2+sum2_pre
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
        // constrain the operation results of And, Or, Xor
        config.fixed_lookup(meta, "BITWISE_LOOKUP");

        config
    }
}

impl<F: Field> BitwiseCircuitConfig<F> {
    /// assign data to circuit table cell
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

    /// set the annotation information of the circuit column
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

    /// fixed lookup, src: Bitwise circuit, target: Fixed circuit table
    /// use lookup table operations to ensure that the operations of And, Or, and Xor are correct.
    pub fn fixed_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
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
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assgin circuit table value
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

/// test code
#[cfg(test)]
mod test {
    use super::*;
    use crate::util::log2_ceil;
    use crate::witness::{bitwise, Witness};
    use eth_types::U256;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Circuit;
    use serde::Serialize;

    const TEST_SIZE: usize = 50;

    // used to test whether the function of Bitwise circuit Lookup is correct
    // Bitwise lookup, src: BitwiseTestCircuit  target: Bitwise circuit
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

        /// Constructor， used to construct config object
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
        /// assign BitwiseTestCircuit rows
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

    /// BitwiseTestCircuitConfig is a Circuit used for testing
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
            // construct config object
            let config = Self::Config::new(meta, ());

            // Lookup logic code
            // used to verify whether acc_0, acc_1, accc_2, sum2 can be correctly looked up
            meta.lookup_any("bitwise test lookup", |meta| {
                // get the value of the specified Column in BitwiseTestCircuit
                let bitwise_entry_tag = meta.query_advice(config.tag, Rotation::cur());
                let bitwise_entry_acc_0 = meta.query_advice(config.acc_0, Rotation::cur());
                let bitwise_entry_acc_1 = meta.query_advice(config.acc_1, Rotation::cur());
                let bitwise_entry_acc_2 = meta.query_advice(config.acc_2, Rotation::cur());
                let bitwise_entry_sum_2 = meta.query_advice(config.sum_2, Rotation::cur());

                // get the value of the specified Column in BitwiseCircuit
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
    ) -> MockProver<Fr> {
        let k = log2_ceil(TEST_SIZE);
        let circuit = BitwiseTestCircuit::<Fr, TEST_SIZE>::new(witness, rows);
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
        // generate bitwise row
        let mut witness = Witness::default();
        (0..BitwiseCircuit::<Fr, TEST_SIZE>::unusable_rows().0)
            .for_each(|_| witness.bitwise.insert(0, Default::default()));

        // because operator1 and operand2 are both u256 values, and each Bitwise operation is 16 bytes that is, 128bit,
        // so operator1 and operand2 need to be split into low 128 bits and high 128 bits.
        let operand1 = U256::from(op1);
        let operand2 = U256::from(op2);

        let operand1_hi = (operand1 >> 128).as_u128();
        let operand1_lo = operand1.low_u128();

        let operand2_hi = (operand2 >> 128).as_u128();
        let operand2_lo = operand2.low_u128();

        // get bitwise rows
        let bitwise_lo_rows = bitwise::Row::from_operation::<Fr>(tag, operand1_lo, operand2_lo);
        let bitwise_hi_rows = bitwise::Row::from_operation::<Fr>(tag, operand1_hi, operand2_hi);

        // add bitwise rows to witness
        witness.bitwise.extend(bitwise_lo_rows);
        witness.bitwise.extend(bitwise_hi_rows);

        // generate bitwise test row
        let bitwise_test_rows = vec![lookup_expect_acc_row];

        witness.print_csv();

        // execution circuit
        let prover = test_simple_bitwise_circuit::<Fr>(witness, bitwise_test_rows);
        prover.assert_satisfied_par();
    }

    /// Test And operation
    #[test]
    fn test_bitwise_acc_lookup1() {
        let tag = Tag::And;
        let operand1 = 0x123456789a_u128;
        let operand2 = 0xff_u128;

        let lookup_expect_acc_row = BitwiseTestRow {
            tag,
            acc_0: U256::from(0x123456789a_u128),
            acc_1: U256::from(0xff_u128),
            acc_2: U256::from(0x123456789a_u128 & 0xff_u128),
            sum_2: U256::from(0x9a_u128), // sum of acc_2 bytes
        };

        test_bitwise_circuit_lookup(tag, operand1, operand2, lookup_expect_acc_row)
    }

    /// Test And operation
    #[test]
    fn test_bitwise_acc_lookup2() {
        let tag = Tag::And;
        let operand1 = 0xabcdef_u128;
        let operand2 = 0xaabbcc_u128;

        let lookup_expect_acc_row = BitwiseTestRow {
            tag,
            acc_0: U256::from(0xabcdef_u128),
            acc_1: U256::from(0xaabbcc_u128),
            acc_2: U256::from(0xaa89cc_u128),
            sum_2: U256::from(0x01ff_u128), // sum of acc_2 bytes
        };

        test_bitwise_circuit_lookup(tag, operand1, operand2, lookup_expect_acc_row)
    }

    /// Test Or operation
    #[test]
    fn test_bitwise_acc_lookup3() {
        let tag = Tag::Or;
        let operand1 = 0xabcdef_u128;
        let operand2 = 0xaabbcc_u128;

        let lookup_expect_acc_row = BitwiseTestRow {
            tag,
            acc_0: U256::from(0xabcdef_u128),
            acc_1: U256::from(0xaabbcc_u128),
            acc_2: U256::from(0xabcdef_u128 | 0xaabbcc_u128),
            sum_2: U256::from(0x0299_u128), // sum of acc_2 bytes
        };

        test_bitwise_circuit_lookup(tag, operand1, operand2, lookup_expect_acc_row)
    }

    /// Test Xor operation
    #[test]
    fn test_bitwise_acc_lookup4() {
        let tag = Tag::Xor;
        let operand1 = 0xabcdef_u128;
        let operand2 = 0xaabbcc_u128;

        let lookup_expect_acc_row = BitwiseTestRow {
            tag,
            acc_0: U256::from(0xabcdef_u128),
            acc_1: U256::from(0xaabbcc_u128),
            acc_2: U256::from(0xabcdef_u128 ^ 0xaabbcc_u128),
            sum_2: U256::from(0x9a_u128), // sum of acc_2 bytes
        };

        test_bitwise_circuit_lookup(tag, operand1, operand2, lookup_expect_acc_row)
    }
}
