use crate::constant::PUBLIC_NUM_VALUES;
use crate::table::{KeccakTable, LookupEntry, PublicTable};
use crate::util::{
    assign_advice_or_fixed_with_u256, assign_advice_or_fixed_with_value, convert_u256_to_64_bytes,
    Challenges, SubCircuit, SubCircuitConfig,
};
use crate::witness::public::{Row, Tag};
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::util::{expr_from_be_bytes, Expr};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Instance, SecondPhase, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_RLC_ACC: usize = 6;
const NUM_U8: usize = 6;
const NUM_RANDOM: usize = 5;
const NUM_ROTATION: usize = 15;
const MULTIPLES_OF_LENGTH: usize = 6;
const NUM_BEGINNING_PADDING_ROW: usize = 15;

const LOG_NUM_PUBLIC_TAG: usize = 5;

#[derive(Clone, Debug)]
pub struct PublicCircuitConfig<F: Field> {
    q_enable: Selector,
    instance_hash: Column<Instance>,
    // tag can be ChainId,BlockCoinbase....; refer witness/public.rs
    tag: Column<Advice>,
    /// block_tx_idx generally represents either block_idx or tx_idx.
    /// When representing tx_idx, it equals to block_idx * 2^32 + tx_idx.
    /// Except for tag=BlockHash, means max_block_idx.
    block_tx_idx: Column<Advice>,
    // values , 4 columns
    values: [Column<Advice>; PUBLIC_NUM_VALUES],
    /// value u8
    /// tag_u8 | block_tx_idx_u8 | value_0_u8 | value_1_u8 | value_2_u8 | value_3_u8
    values_u8_vec: [Column<Advice>; NUM_U8],

    /// value rlc acc
    /// tag_u8_rlc_acc | block_tx_idx_u8_rlc_acc | value_0_u8_rlc_acc | value_1_u8_rlc_acc | value_2_u8_rlc_acc | value_3_u8_rlc_acc
    rlc_acc_vec: [Column<Advice>; NUM_RLC_ACC],

    /// random | random^2 | random^3 | random^4 | random^5
    random_vec: [Column<Advice>; NUM_RANDOM],

    // challenge | challenge^2 | challenge^3....challenge^length
    challenge: Column<Advice>,

    /// the row counter starts at 0 and increases automatically
    cnt: Column<Advice>,
    /// the total length of row
    length: Column<Advice>,

    /// High 128 bits of the contract bytecode hash result
    hash_hi: Column<Advice>,
    // Low 128 bits of the contract bytecode hash result
    hash_lo: Column<Advice>,

    /// Tag for arithmetic operation type
    tag_binary: BinaryNumberConfig<Tag, LOG_NUM_PUBLIC_TAG>,

    /// first valid row
    pub is_first_valid_row: IsZeroConfig<F>,

    /// last valid row
    pub is_last_valid_row: IsZeroConfig<F>,

    // table used for lookup
    keccak_table: KeccakTable,
}

pub struct PublicCircuitConfigArgs {
    pub q_enable: Selector,
    // refer table.rs PublicTable
    pub public_table: PublicTable,
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges,
    pub instance_hash: Column<Instance>,
}

impl<F: Field> SubCircuitConfig<F> for PublicCircuitConfig<F> {
    type ConfigArgs = PublicCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            public_table,
            challenges,
            keccak_table,
            instance_hash,
        }: Self::ConfigArgs,
    ) -> Self {
        // unwrap public_table
        let PublicTable {
            // tag can be ChainId,BlockCoinbase....; refer witness/public.rs
            tag,
            // block_tx_idx (start from 1), except for tag=BlockHash, means recent block number diff (1...256)
            block_tx_idx,
            // values , 4 columns
            values,
        } = public_table;
        let challenges_expr = challenges.exprs(meta);

        // define advice column
        let values_u8_vec = std::array::from_fn(|_| meta.advice_column());
        let rlc_acc_vec = std::array::from_fn(|_| meta.advice_column_in(SecondPhase));
        let random_vec = std::array::from_fn(|_| meta.advice_column_in(SecondPhase));
        let challenge_col = meta.advice_column_in(SecondPhase);
        let hash_hi = meta.advice_column();
        let hash_lo = meta.advice_column();
        let cnt = meta.advice_column();
        let length = meta.advice_column();
        let tag_binary = BinaryNumberChip::configure(meta, q_enable.clone(), None);

        // define instance column
        meta.enable_equality(instance_hash);
        meta.enable_equality(hash_hi);
        meta.enable_equality(hash_lo);

        // cnt flag
        let _is_first_valid_row_inv = meta.advice_column();
        let is_first_valid_row = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt = meta.query_advice(cnt, Rotation::cur());
                cnt - NUM_BEGINNING_PADDING_ROW.expr()
            },
            _is_first_valid_row_inv,
        );

        let _is_last_valid_row_inv = meta.advice_column();
        let is_last_valid_row = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt = meta.query_advice(cnt, Rotation::cur());
                let length = meta.query_advice(length, Rotation::cur());
                length + NUM_BEGINNING_PADDING_ROW.expr() - cnt - 1.expr()
            },
            _is_last_valid_row_inv,
        );

        let config = Self {
            q_enable,
            instance_hash,
            tag,
            block_tx_idx,
            values,
            values_u8_vec,
            rlc_acc_vec,
            random_vec,
            challenge: challenge_col,
            cnt,
            length,
            hash_hi,
            hash_lo,
            tag_binary,
            is_first_valid_row,
            is_last_valid_row,
            keccak_table,
        };

        // challenge constrains
        meta.create_gate("PUBLIC_CHALLENGE_RANDOM", |meta| {
            let challenge_original = challenges_expr.keccak_input();
            let q_enable = meta.query_selector(config.q_enable);
            let challenge_cur = meta.query_advice(config.challenge, Rotation::cur());
            let challenge_prev = meta.query_advice(config.challenge, Rotation::prev());
            let is_first_valid_row = config.is_first_valid_row.expr();
            let is_last_valid_row = config.is_last_valid_row.expr();

            let (mut random_vec_cur, mut random_vec_prev) = (vec![], vec![]);
            for i in 0..NUM_RANDOM {
                random_vec_cur.push(meta.query_advice(config.random_vec[i], Rotation::cur()));
                random_vec_prev.push(meta.query_advice(config.random_vec[i], Rotation::prev()));
            }

            let mut constrains = vec![];

            // challenge constrains
            // constrains.extend(vec![
            //     // in the first row(cnt==0) challenge == challenge_original
            //     q_enable.clone()
            //         * is_first_row.clone()
            //         * (challenge_cur.clone() - challenge_original.clone()),
            //     //non-first row challenge_cur = challenge_prev*challenge_original
            //     q_enable.clone()
            //         * (1.expr()
            //             - is_first_valid_row.clone()
            //                 * (challenge_cur.clone()
            //                     - challenge_prev * challenge_original.clone())),
            // ]);

            // random constrains
            for i in 0..NUM_RANDOM {
                // if it is not the first row, the random of the current row is equal to the random of the previous row
                constrains.push(
                    q_enable.clone()
                        * (1.expr() - is_first_valid_row.clone())
                        * (random_vec_cur[i].clone() - random_vec_prev[i].clone()),
                );

                // for each row:
                //   random = challenge^length
                //   random^2 = random * random
                //   random^3 = random^2 * random
                //   random^4 = random^3 * random
                //   random^5 = random^4 * random
                if i == 0 {
                    constrains.push(
                        q_enable.clone()
                            * is_last_valid_row.clone()
                            * (random_vec_cur[i].clone() - challenge_cur.clone()),
                    );
                } else {
                    constrains.push(
                        q_enable.clone()
                            * (random_vec_cur[i].clone()
                                - random_vec_cur[i - 1].clone() * random_vec_cur[0].clone()),
                    )
                }
            }

            constrains
        });

        // cnt and length constrains
        // the cnt value of the beginning padding row is 0 and the length value is length
        meta.create_gate("PUBLIC_CNT_LENGTH", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let length_prev = meta.query_advice(config.length, Rotation::prev());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            let is_first_valid_row = config.is_first_valid_row.expr();

            let length = meta.query_advice(config.length, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            vec![
                // the cnt value is increasing, and the difference between every two rows of cnt is 1
                q_enable.clone() * (cnt.clone() - cnt_prev - 1.expr()),
                // the values of length are the same
                q_enable.clone() * (length.clone() - length_prev),
            ]
        });

        // rlc_acc constrains
        meta.create_gate("PUBLIC_RLC_ACC", |meta| {
            let challenge = challenges_expr.keccak_input();
            let q_enable = meta.query_selector(config.q_enable);
            let is_first_valid_row = config.is_first_valid_row.expr();

            let (mut values_u8_vec_cur, mut rlc_acc_vec_cur, mut rlc_acc_vec_prev) =
                (vec![], vec![], vec![]);
            for i in 0..NUM_RLC_ACC {
                values_u8_vec_cur.push(meta.query_advice(config.values_u8_vec[i], Rotation::cur()));
                rlc_acc_vec_cur.push(meta.query_advice(config.rlc_acc_vec[i], Rotation::cur()));
                rlc_acc_vec_prev.push(meta.query_advice(config.rlc_acc_vec[i], Rotation::prev()));
            }

            // get constrains
            let mut constrains = vec![];
            for i in 0..NUM_RLC_ACC {
                // in the first row (cnt=1), rlc_acc is equal to value_u8
                // because when cnt=1, rlc_acc_cur = rlc_acc_prev(cnt=0, value is zero) * challenge + value_cur, so rlc_acc_cur = value_cur
                constrains.push(
                    q_enable.clone()
                        * is_first_valid_row.clone()
                        * (rlc_acc_vec_cur[i].clone() - values_u8_vec_cur[i].clone()),
                );

                // not the first row， rlc_acc = rlc_acc_prev*challenge + value_u8
                constrains.push(
                    q_enable.clone()
                        * (1.expr() - is_first_valid_row.clone())
                        * (rlc_acc_vec_cur[i].clone()
                            - rlc_acc_vec_prev[i].clone() * challenge.clone()
                            - values_u8_vec_cur[i].clone()),
                );
            }
            constrains
        });

        // values u8 constrains
        // if tag != nil && tag != txCalldata && tag != txLogData, then src_value == target_value, for example, src_tag == target_tag, src_block_tx_idx == target_block_tx_idx ...
        //    target_tag = tag_u8.Rotation(-15)*2^120 + tag_u8.Rotation(-14)*2^112 + tag_u8.Rotation(-13)2^104 + tag_u8.Rotation(-12)*2^96 + ...tag_u8.Rotation(-1)*2^8 + tag_u8.Rotation::cur()
        // if tag != nil && (tag == txCallData || tag == txLogData) then, value1 == value1_u8 && value0_u8 == 0 && value2_u8 == 0 && value3_u8 == 0 && tag_u8 == 0 && block_tx_idx == 0
        meta.create_gate("PUBLIC_U8_AND_VALUE", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let tag = meta.query_advice(config.tag, Rotation::cur());
            let block_tx_idx = meta.query_advice(config.block_tx_idx, Rotation::cur());
            let value0 = meta.query_advice(config.values[0], Rotation::cur());
            let value1 = meta.query_advice(config.values[1], Rotation::cur());
            let value2 = meta.query_advice(config.values[2], Rotation::cur());
            let value3 = meta.query_advice(config.values[3], Rotation::cur());

            let tag_is_nil = config.tag_binary.value_equals(Tag::Nil, Rotation::cur())(meta);
            let tag_is_tx_calldata =
                config
                    .tag_binary
                    .value_equals(Tag::TxCalldata, Rotation::cur())(meta);
            let tag_is_tx_logdata =
                config
                    .tag_binary
                    .value_equals(Tag::TxLogData, Rotation::cur())(meta);

            let tag_is_not_nil = 1.expr() - tag_is_nil.clone();
            let tag_is_not_tx_calldata = 1.expr() - tag_is_tx_calldata.clone();
            let tag_is_not_tx_logdata = 1.expr() - tag_is_tx_logdata.clone();

            // tag | block_tx_idx | value0 | value1 | value2 | value3
            let src_value_vec = vec![tag, block_tx_idx, value0.clone(), value1, value2, value3];

            // =================== calc target value ===================
            // get u8 expression
            // for example:
            //  tag_u8.Rotation(-15)
            //  tag_u8.Rotation(-14)
            //  tag_u8.Rotation(-13)
            //  ...
            //  tag_u8.Rotation(-1)
            //  tag_u8.Rotation::cur()
            let mut u8_vec_vec: Vec<Vec<Expression<F>>> = vec![vec![]; NUM_U8]; // [tag_u8_vec, block_tx_idx_u8_vec, value0_u8_vec, value2_u8_vec, value3_u8_vec] (Rotation::cur() ~ Rotation(-15))
            let mut u8_cur_vec = vec![]; // tag_u8_cur | block_tx_idx_u8_cur | value0_u8_cur | value1_u8_cur | value2_u8_cur | value3_u8_cur
            for i in 0..=NUM_ROTATION {
                // i:0, rotation=-(15-0)=-15
                // i:1, rotation=-(15-1)=-14
                // ...
                // i:15, rotation=-(15-15)=0 (Rotation::cur())
                let at = -(NUM_ROTATION as i32 - i as i32);
                for (i, u8_vec) in u8_vec_vec.iter_mut().enumerate() {
                    let v_u8 = meta.query_advice(config.values_u8_vec[i], Rotation(at));
                    if at == 0 {
                        u8_cur_vec.push(v_u8.clone());
                    }
                    u8_vec.push(v_u8);
                }
            }

            // tag | block_tx_idx | value0 | value1 | value2 | value3
            // calc target_value(u8_vec is big endian)
            // for example:
            //  target_tag = tag_u8.Rotation(-15)*2^120 + tag_u8.Rotation(-14)*2^112 + tag_u8.Rotation(-13)2^104 + tag_u8.Rotation(-12)*2^96 + ...tag_u8.Rotation(-1)*2^8 + tag_u8.Rotation::cur()
            let mut target_value_vec = vec![];
            for u8_vec in u8_vec_vec {
                target_value_vec.push(expr_from_be_bytes(&u8_vec))
            }

            // =================== constrains ===================
            let mut constrains = vec![];
            for i in 0..NUM_U8 {
                // if tag != nil && tag != txCalldata && tag != txLogData,
                // then src_value=target_value
                // todo: is degree greater than 9?
                constrains.push(
                    q_enable.clone()
                        * tag_is_not_nil.clone()
                        * tag_is_not_tx_calldata.clone()
                        * tag_is_not_tx_logdata.clone()
                        * (target_value_vec[i].clone() - src_value_vec[i].clone()),
                );

                // if tag != nil && (tag == txCallData || tag == txLogData),
                // then value1 == value1_u8 &&
                //   value0_u8 == 0 && value2_u8 == 0 && value3_u8 == 0 && tag_u8 == 0 && block_tx_idx == 0
                if i == 3 {
                    constrains.push(
                        q_enable.clone()
                            * tag_is_not_nil.clone()
                            * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                            * (u8_cur_vec[i].clone() - src_value_vec[i].clone()),
                    );
                } else {
                    constrains.push(
                        q_enable.clone()
                            * tag_is_not_nil.clone()
                            * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                            * u8_cur_vec[i].clone(),
                    );
                }
            }

            constrains
        });

        meta.create_gate("PUBLIC_TAG_AND_VALUE", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let tag = meta.query_advice(config.tag, Rotation::cur());
            let block_tx_idx = meta.query_advice(config.block_tx_idx, Rotation::cur());
            let value0 = meta.query_advice(config.values[0], Rotation::cur());
            let value1 = meta.query_advice(config.values[1], Rotation::cur());
            let value2 = meta.query_advice(config.values[2], Rotation::cur());
            let value3 = meta.query_advice(config.values[3], Rotation::cur());

            let tag_prev = meta.query_advice(config.tag, Rotation::prev());
            let block_tx_idx_prev = meta.query_advice(config.block_tx_idx, Rotation::prev());
            let value0_prev = meta.query_advice(config.values[0], Rotation::prev());
            let value2_prev = meta.query_advice(config.values[2], Rotation::prev());

            let tag_is_nil = config.tag_binary.value_equals(Tag::Nil, Rotation::cur())(meta);
            let tag_is_tx_calldata =
                config
                    .tag_binary
                    .value_equals(Tag::TxCalldata, Rotation::cur())(meta);
            let tag_is_tx_logdata =
                config
                    .tag_binary
                    .value_equals(Tag::TxLogData, Rotation::cur())(meta);

            let tag_is_not_nil = 1.expr() - tag_is_nil.clone();
            let tag_is_not_tx_calldata = 1.expr() - tag_is_tx_calldata.clone();
            let tag_is_not_tx_logdata = 1.expr() - tag_is_tx_logdata.clone();

            let mut constrains = vec![];

            // if tag != nil && tag != txCalldata && tag != txLogData,  (value is already constrained in the PUBLIC_U8_AND_VALUE gate)
            // then tag.Rotation(-1) == nil
            //      tag.Rotation(-2) == nil
            //      tag.Rotation(-3) == nil
            //      ...
            //      tag.Rotation(-15) == nil
            for rotation in 1..NUM_ROTATION {
                let tag_is_nil_rotation = config
                    .tag_binary
                    .value_equals(Tag::Nil, Rotation(-(rotation as i32)))(
                    meta
                );
                let tag_rotation = meta.query_advice(config.tag, Rotation(-(rotation as i32)));
                // todo: is degree greater than 9?
                constrains.push(
                    q_enable.clone()
                        * tag_is_not_nil.clone()
                        * tag_is_not_tx_calldata.clone()
                        * tag_is_not_tx_logdata.clone()
                        * tag_is_nil_rotation
                        * tag_rotation,
                );
            }

            // if tag != nil && (tag == txCallData || tag == txLogData) && value0(idx_cur) != 0,
            // then value0_cur(idx_cur) == value0_prev+1 (idx_cur+1)
            //      tag_cur == tag_prev
            //      block_tx_idx_cur == block_tx_idx_prev
            //      value2 == value2_prev
            //      value3 == 0
            constrains.extend(vec![
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value0.clone() // there are only two cases for value0: 0 and non-0
                    * (value0.clone() - value0_prev - 1.expr()),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value0.clone()
                    * (tag.clone() - tag_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value0.clone()
                    * (block_tx_idx.clone() - block_tx_idx_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value0.clone()
                    * (value2.clone() - value2_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value0.clone()
                    * value3.clone(),
            ]);

            // if tag == nil,
            // then tag == 0
            //      block_tx_idx_cur==0
            //      value0==0
            //      value1==0
            //      value2==0
            //      value3==0
            constrains.extend(vec![
                q_enable.clone() * tag_is_nil.clone() * tag,
                q_enable.clone() * tag_is_nil.clone() * block_tx_idx,
                q_enable.clone() * tag_is_nil.clone() * value0,
                q_enable.clone() * tag_is_nil.clone() * value1,
                q_enable.clone() * tag_is_nil.clone() * value2,
                q_enable.clone() * tag_is_nil.clone() * value3,
            ]);
            constrains
        });

        // add all lookup constraints here
        config.keccak_lookup(meta, "PUBLIC_LOOKUP_KECCAK_HASH");

        config
    }
}

impl<F: Field> PublicCircuitConfig<F> {
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        challenges: &Challenges<Value<F>>,
        witness: &Witness,
        num_padding_begin: usize,
    ) -> Result<(), Error> {
        let challenge = challenges.keccak_input();

        // assign begin padding row
        let default_random_vec = vec![Value::known(F::ZERO); NUM_RANDOM];
        let mut default_rlc_acc_vec_prev: Vec<Value<F>> = vec![Value::known(F::ZERO); NUM_RLC_ACC];
        for offset in 0..num_padding_begin {
            self.assign_row(
                region,
                offset,
                &witness.public[offset],
                Value::known(F::ZERO),
                &default_random_vec,
                &mut default_rlc_acc_vec_prev,
            )?;
            self.assign_challenge_row(region, offset, Value::known(F::ZERO))?;
        }

        // assign valid row

        // calc random, random = challenge^length
        let mut challenge_vec = vec![challenge];
        for i in 1..witness.public.len() - num_padding_begin {
            challenge_vec.push(challenge_vec[i - 1] * challenge)
        }

        // random | random^2 | random^3 | random^4 | random^5
        let random = challenge_vec.last().unwrap().clone();
        let mut random_vec: Vec<Value<F>> = vec![random];
        for i in 1..NUM_RANDOM {
            random_vec.push(random_vec[i - 1] * random);
        }

        // | tag_u8_rlc_acc | block_tx_idx_u8_rlc_acc | value_0_u8_rlc_acc | value_1_u8_rlc_acc | value_2_u8_rlc_acc | value_3_u8_rlc_acc
        let mut rlc_acc_vec_prev: Vec<Value<F>> = vec![Value::known(F::ZERO); NUM_RLC_ACC];

        // has one padding row, cnt=0
        // assign value to cell
        for offset in num_padding_begin..witness.public.len() {
            // assign
            self.assign_row(
                region,
                offset,
                &witness.public[offset],
                challenge,
                &random_vec,
                &mut rlc_acc_vec_prev,
            )?;
            // assign challenge column
            self.assign_challenge_row(region, offset, challenge_vec[offset - num_padding_begin])?;
        }

        Ok(())
    }

    pub fn assign_from_instance_with_region(
        &self,
        region: &mut Region<'_, F>,
        row_num: usize,
        num_padding_begin: usize,
    ) -> Result<(), Error> {
        let row = 0usize;
        let offset = num_padding_begin;
        let mut hash_hi_prev = region.assign_advice_from_instance(
            || "hash_hi",
            self.instance_hash,
            row,
            self.hash_hi,
            offset,
        )?;
        let mut hash_lo_prev = region.assign_advice_from_instance(
            || "hash_hi",
            self.instance_hash,
            row + 1,
            self.hash_lo,
            offset,
        )?;
        for o in offset + 1..row_num {
            hash_hi_prev = hash_hi_prev.copy_advice(|| "hash_hi", region, self.hash_hi, o)?;
            hash_lo_prev = hash_lo_prev.copy_advice(|| "hash_lo", region, self.hash_lo, o)?;
        }

        Ok(())
    }

    fn assign_challenge_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        assign_advice_or_fixed_with_value(region, offset, challenge, self.challenge)?;
        Ok(())
    }

    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
        challenge: Value<F>,
        random_vec: &Vec<Value<F>>,
        rlc_acc_vec_prev: &mut Vec<Value<F>>,
    ) -> Result<(), Error> {
        let values_u8_vec = vec![
            row.tag_u8.unwrap_or_default(),
            row.block_tx_idx_u8.unwrap_or_default(),
            row.value_0_u8.unwrap_or_default(),
            row.value_1_u8.unwrap_or_default(),
            row.value_2_u8.unwrap_or_default(),
            row.value_3_u8.unwrap_or_default(),
        ];

        // calc rlc_acc
        // first row, rlc_acc_prev is zero
        let mut rlc_acc_vec: Vec<Value<F>> = vec![];
        for (i, u8_v) in values_u8_vec.iter().enumerate() {
            let v = Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(u8_v)));
            // calc rlc_acc
            let rlc_acc = rlc_acc_vec_prev[i] * challenge + v;
            // update rlc_acc prev
            rlc_acc_vec_prev[i] = rlc_acc;
            // save rlc_acc
            rlc_acc_vec.push(rlc_acc)
        }

        let tag_binary = BinaryNumberChip::construct(self.tag_binary);
        let is_first_valid_row = IsZeroChip::construct(self.is_first_valid_row.clone());
        let is_last_valid_row = IsZeroChip::construct(self.is_last_valid_row.clone());

        // original value
        assign_advice_or_fixed_with_u256(region, offset, &U256::from(row.tag as u8), self.tag)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.block_tx_idx.unwrap_or_default(),
            self.block_tx_idx,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.value_0.unwrap_or_default(),
            self.values[0],
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.value_1.unwrap_or_default(),
            self.values[1],
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.value_2.unwrap_or_default(),
            self.values[2],
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.value_3.unwrap_or_default(),
            self.values[3],
        )?;

        // assign u8_vec
        for (i, v_u8) in values_u8_vec.iter().enumerate() {
            assign_advice_or_fixed_with_u256(region, offset, v_u8, self.values_u8_vec[i])?;
        }

        // assign rlc_acc_vec
        for (i, rlc_acc) in rlc_acc_vec.into_iter().enumerate() {
            assign_advice_or_fixed_with_value(region, offset, rlc_acc, self.rlc_acc_vec[i])?;
        }

        // assign random
        for (i, random) in random_vec.into_iter().enumerate() {
            assign_advice_or_fixed_with_value(region, offset, random.clone(), self.random_vec[i])?;
        }

        // assign cnt and length
        assign_advice_or_fixed_with_u256(region, offset, &row.cnt.unwrap_or_default(), self.cnt)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.length.unwrap_or_default(),
            self.length,
        )?;

        // assign tag_binary
        tag_binary.assign(region, offset, &row.tag)?;

        // assign flag
        let length_v =
            F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.length.unwrap_or_default()));
        let cnt_v = F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt.unwrap_or_default()));
        is_first_valid_row.assign(
            region,
            offset,
            Value::known(cnt_v - F::from(NUM_BEGINNING_PADDING_ROW as u64)),
        )?;
        is_last_valid_row.assign(
            region,
            offset,
            Value::known(length_v + F::from(NUM_BEGINNING_PADDING_ROW as u64) - cnt_v - F::from(1)),
        )?;
        Ok(())
    }

    /// set the annotation information of the circuit colum
    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "PUBLIC_tag", self.tag);
        region.name_column(|| "PUBLIC_block_tx_idx", self.block_tx_idx);

        for i in 0..PUBLIC_NUM_VALUES {
            region.name_column(|| format!("PUBLIC_value_{}", i), self.values[i]);
        }

        for i in 0..NUM_U8 {
            region.name_column(|| format!("PUBLIC_value_u8_{}", i), self.values_u8_vec[i]);
        }

        for i in 0..NUM_RLC_ACC {
            region.name_column(
                || format!("PUBLIC_value_u8_{}_rlc_acc", i),
                self.rlc_acc_vec[i],
            );
        }

        for i in 0..NUM_RANDOM {
            region.name_column(|| format!("PUBLIC_random^{}", i), self.random_vec[i]);
        }

        region.name_column(|| "PUBLIC_cnt", self.cnt);
        region.name_column(|| "PUBLIC_length", self.length);

        region.name_column(|| "PUBLIC_hash_hi", self.hash_hi);
        region.name_column(|| "PUBLIC_hash_lo", self.hash_lo);

        self.is_first_valid_row
            .annotate_columns_in_region(region, "PUBLIC_is_first_valid_row");
        self.is_last_valid_row
            .annotate_columns_in_region(region, "PUBLIC_is_last_valid_row");
    }

    // lookup hash
    pub fn keccak_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        meta.lookup_any(name, |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let is_last_valid_row = self.is_last_valid_row.expr();
            let (mut rlc_acc_vec_cur, mut random_vec_cur) = (vec![], vec![]);

            // get last_row rlc_acc
            // tag_u8_rlc_acc | block_tx_idx_u8_rlc_acc | value_0_u8_rlc_acc | value_1_u8_rlc_acc | value_2_u8_rlc_acc | value_3_u8_rlc_acc
            for i in 0..NUM_RLC_ACC {
                rlc_acc_vec_cur.push(meta.query_advice(self.rlc_acc_vec[i], Rotation::cur()));
            }

            // random | random^2 | random^3 | random^4 | random^5
            for i in 0..NUM_RANDOM {
                random_vec_cur.push(meta.query_advice(self.random_vec[i], Rotation::cur()));
            }

            // concat_rlc_acc = tag_u8_rlc_acc * random^5 + block_tx_idx_u8_rlc_acc * random^4 + value_0_u8_rlc_acc random^3 +
            //                  value_1_u8_rlc_acc * random^2 + value_2_u8_rlc_acc * random + value_3_u8_rlc_acc
            let mut concat_rlc_acc = rlc_acc_vec_cur[NUM_RLC_ACC - 1].clone();
            for i in 0..NUM_RANDOM {
                // if i=0, then NUM_RANDOM - i - 1 is 4 (random^5)
                // if i=1, then NUM_RANDOM - i - 1 is 3 (random^4)
                // if i=2, then NUM_RANDOM - i - 1 is 2 (random^3)
                // if i=3, then NUM_RANDOM - i - 1 is 1 (random^2)
                // if i=4, then NUM_RANDOM - i - 1 is 0 (random)
                concat_rlc_acc = concat_rlc_acc
                    + rlc_acc_vec_cur[i].clone() * random_vec_cur[NUM_RANDOM - i - 1].clone();
            }

            let length = meta.query_advice(self.length, Rotation::cur());
            let keecak_entry = LookupEntry::Keccak {
                input_len: length * MULTIPLES_OF_LENGTH.expr(),
                input_rlc: concat_rlc_acc,
                output_hi: meta.query_advice(self.hash_hi, Rotation::cur()),
                output_lo: meta.query_advice(self.hash_lo, Rotation::cur()),
            };

            let keecak_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .keccak_table
                .get_lookup_vector(meta, keecak_entry.clone());

            keecak_lookup_vec
                .into_iter()
                .map(|(left, right)| (q_enable.clone() * is_last_valid_row.clone() * left, right))
                .collect()
        });
    }
}

#[derive(Clone, Default, Debug)]
pub struct PublicCircuit<F: Field> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for PublicCircuit<F> {
    type Config = PublicCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        PublicCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }
    // instance return vector of vector
    /// +-----+-----------------------+--------+--------+--------+--------+
    /// | tag | block_tx_idx | value0 | value1 | value2 | value3 |
    fn instance(&self) -> Vec<Vec<F>> {
        self.witness.get_public_instance()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, _) = Self::unusable_rows();
        // assign row and calc rlc_acc
        layouter.assign_region(
            || "public circuit",
            |mut region| {
                // assign value to cell
                config.assign_with_region(
                    &mut region,
                    challenges,
                    &self.witness,
                    num_padding_begin,
                )?;

                // assign value from instance
                config.assign_from_instance_with_region(
                    &mut region,
                    self.witness.public.len(),
                    num_padding_begin,
                )?;

                // sub circuit need to enable selector
                for offset in num_padding_begin..self.witness.public.len() {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (NUM_BEGINNING_PADDING_ROW, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        // bytecode witness length plus must-have padding in the end
        num_padding_begin + witness.public.len() + num_padding_end
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::keccak_circuit::{KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs};
    use crate::util::{assign_advice_or_fixed_with_u256, chunk_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Advice, Circuit};
    use halo2_proofs::poly::Rotation;

    const TEST_MAX_NUM_ROW: usize = 65536; // k=16
    #[derive(Clone, Default, Debug)]
    pub struct PublicTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub public_circuit: PublicCircuit<F>,
        pub keccak_circuit: KeccakCircuit<F, MAX_NUM_ROW>,
    }

    #[derive(Clone)]
    pub struct PublicTestCircuitConfig<F: Field> {
        pub public_circuit: PublicCircuitConfig<F>,
        pub keccak_circuit: KeccakCircuitConfig<F>,
        pub tag: Column<Advice>,
        pub block_tx_idx: Column<Advice>,
        pub values: [Column<Advice>; PUBLIC_NUM_VALUES],
        pub challenges: Challenges,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for PublicTestCircuit<F, MAX_NUM_ROW> {
        type Config = PublicTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // construct public table
            let instance_hash = PublicTable::construct_hash_instance_column(meta);
            let q_enable_public = meta.complex_selector();
            let public_table = PublicTable::construct(meta);

            // construct keccak table
            let keccak_table = KeccakTable::construct(meta);

            let challenges = Challenges::construct(meta);
            let public_circuit = PublicCircuitConfig::new(
                meta,
                PublicCircuitConfigArgs {
                    q_enable: q_enable_public,
                    public_table,
                    keccak_table,
                    challenges,
                    instance_hash,
                },
            );

            let keccak_circuit = KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table,
                    challenges,
                },
            );

            let config = PublicTestCircuitConfig {
                public_circuit,
                keccak_circuit,
                tag: meta.advice_column(),
                block_tx_idx: meta.advice_column(),
                values: std::array::from_fn(|_| meta.advice_column()),
                challenges,
            };

            // lookup constraints
            meta.lookup_any("test lookup", |meta| {
                let mut v = vec![
                    // tag lookup constraints
                    (
                        // query tag advice
                        meta.query_advice(config.tag, Rotation::cur()),
                        // query tag instance
                        meta.query_advice(config.public_circuit.tag, Rotation::cur()),
                    ),
                    // block_tx_idx lookup constraints
                    (
                        // query block_tx_idx advice
                        meta.query_advice(config.block_tx_idx, Rotation::cur()),
                        // query block_tx_idx instance
                        meta.query_advice(config.public_circuit.block_tx_idx, Rotation::cur()),
                    ),
                ];
                // values lookup constraints
                v.append(
                    &mut (0..PUBLIC_NUM_VALUES)
                        .map(|i| {
                            (
                                // query value advice
                                meta.query_advice(config.values[i], Rotation::cur()),
                                // query value instance
                                meta.query_advice(config.public_circuit.values[i], Rotation::cur()),
                            )
                        })
                        .collect(),
                );
                v
            });
            config
        }
        #[rustfmt::skip]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.public_circuit.synthesize_sub(&config.public_circuit, &mut layouter,&challenges)?;
            self.keccak_circuit.synthesize_sub(
                &config.keccak_circuit,
                &mut layouter,
                &challenges,
            )?;
            // assign values
            layouter.assign_region(
                || "TEST",
                |mut region| {
                    for (offset, row) in self.public_circuit.witness.public.iter().enumerate() {
                        assign_advice_or_fixed_with_u256(&mut region, offset, &(row.tag as u8).into(), config.tag)?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.block_tx_idx.unwrap_or_default(), config.block_tx_idx)?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_0.unwrap_or_default(), config.values[0])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_1.unwrap_or_default(), config.values[1])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_2.unwrap_or_default(), config.values[2])?;
                        assign_advice_or_fixed_with_u256(&mut region, offset, &row.value_3.unwrap_or_default(), config.values[3])?;
                    }
                    Ok(())
                },
            )        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> PublicTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness) -> Self {
            Self {
                keccak_circuit: KeccakCircuit::new_from_witness(&witness),
                public_circuit: PublicCircuit::new_from_witness(&witness),
            }
        }

        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.keccak_circuit.instance());
            vec.extend(self.public_circuit.instance());
            vec
        }
    }

    fn test_public_circuit(witness: Witness) -> MockProver<Fp> {
        // ceiling of log2(MAX_NUM_ROW)
        let k = log2_ceil(TEST_MAX_NUM_ROW);
        let circuit = PublicTestCircuit::<Fp, TEST_MAX_NUM_ROW>::new(witness);
        // get circuit instances , vec<vec<Fr>>
        let instance = circuit.instance();
        // mock run circuit
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_public_parser() {
        // load instructions
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        // parse trace
        let trace = trace_parser::trace_program(&machine_code, &[]);
        // construct witness using trace
        let witness: Witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        // output witness as csv
        //witness.print_csv();
        // witness prove
        let prover = test_public_circuit(witness);
        // any circuit fail will panic
        prover.assert_satisfied_par();
    }
}
