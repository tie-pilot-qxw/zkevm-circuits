// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{
    PUBLIC_NUM_ALL_VALUE, PUBLIC_NUM_BEGINNING_PADDING_ROW, PUBLIC_NUM_VALUES,
    PUBLIC_NUM_VALUES_U8_ROW,
};
use crate::table::{KeccakTable, LookupEntry, PublicTable};
use crate::util::{
    assign_advice_or_fixed_with_u256, assign_advice_or_fixed_with_value, convert_u256_to_64_bytes,
    Challenges, SubCircuit, SubCircuitConfig,
};
use crate::witness::public::{Row, Tag};
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::{expr_from_be_bytes, Expr};
use halo2_proofs::circuit::{Cell, Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Instance, SecondPhase, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_RLC_ACC: usize = PUBLIC_NUM_ALL_VALUE;
const NUM_U8: usize = PUBLIC_NUM_ALL_VALUE;
const NUM_RANDOM: usize = 5;
const MULTIPLES_OF_LENGTH: usize = PUBLIC_NUM_ALL_VALUE;
const NUM_ROTATION: usize = PUBLIC_NUM_VALUES_U8_ROW - 1;

const INSTANCE_HASH_HI_ROW: usize = 0;
const INSTANCE_HASH_LO_ROW: usize = 1;

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

    /// the row counter starts at 1 and increases automatically
    cnt: Column<Advice>,
    /// the total length of row
    length: Column<Advice>,

    /// High 128 bits of the contract bytecode hash result
    hash_hi: Column<Advice>,
    /// Low 128 bits of the contract bytecode hash result
    hash_lo: Column<Advice>,

    /// cnt flag
    /// is_first_valid_row: cnt == 1
    pub is_first_valid_row: IsZeroConfig<F>,

    /// last valid row
    /// is_last_valid_row: cnt != 0 && cnt_next == 0 && cnt == length
    pub is_last_valid_row: IsZeroConfig<F>,

    /// cnt_is_zero: cnt == 0
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,

    /// tag flag
    pub tag_is_nil_val: Column<Advice>,
    pub tag_is_tx_logdata_val: Column<Advice>,
    pub tag_is_tx_calldata_val: Column<Advice>,

    pub tag_is_nil: IsZeroWithRotationConfig<F>,
    pub tag_is_tx_logdata: IsZeroWithRotationConfig<F>,
    pub tag_is_tx_calldata: IsZeroWithRotationConfig<F>,

    /// used to determine whether data_idx(value2) is 0 when tag is txLogData or txCallData
    /// when tag is txLogData or txCallData and idx(value2) is 0, value3(data) will be split into 16 bytes.
    pub value2_is_zero: IsZeroWithRotationConfig<F>,

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
        let tag_is_nil_val = meta.advice_column();
        let tag_is_tx_logdata_val = meta.advice_column();
        let tag_is_tx_calldata_val = meta.advice_column();

        // define instance column
        meta.enable_equality(instance_hash);
        meta.enable_equality(hash_hi);
        meta.enable_equality(hash_lo);

        // cnt flag
        let cnt_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            cnt,
            None,
        );

        let _is_first_valid_row_inv = meta.advice_column();
        let is_first_valid_row = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt = meta.query_advice(cnt, Rotation::cur());
                cnt - 1.expr()
            },
            _is_first_valid_row_inv,
        );

        let _is_last_valid_row_inv = meta.advice_column();
        let is_last_valid_row = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt_cur_is_zero = cnt_is_zero.expr_at(meta, Rotation::cur());
                let cnt_next_is_zero = cnt_is_zero.expr_at(meta, Rotation::next());
                // cnt != 0 && cnt_next == 0
                cnt_next_is_zero - cnt_cur_is_zero - 1.expr()
            },
            _is_last_valid_row_inv,
        );

        // tag flag
        let tag_is_nil = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            tag_is_nil_val,
            None,
        );
        let tag_is_tx_logdata = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            tag_is_tx_logdata_val,
            None,
        );
        let tag_is_tx_calldata = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            tag_is_tx_calldata_val,
            None,
        );

        // value0 is zero
        let value2_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            values[2],
            None,
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
            is_first_valid_row,
            is_last_valid_row,
            cnt_is_zero,
            tag_is_nil_val,
            tag_is_tx_logdata_val,
            tag_is_tx_calldata_val,
            tag_is_nil,
            tag_is_tx_logdata,
            tag_is_tx_calldata,
            value2_is_zero,
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
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let is_valid_row = 1.expr() - cnt_is_zero;

            let (mut random_vec_cur, mut random_vec_prev) = (vec![], vec![]);
            for i in 0..NUM_RANDOM {
                random_vec_cur.push(meta.query_advice(config.random_vec[i], Rotation::cur()));
                random_vec_prev.push(meta.query_advice(config.random_vec[i], Rotation::prev()));
            }

            let mut constrains = vec![];

            // challenge constrains
            constrains.extend(vec![
                // if the first row(cnt==1), then challenge == challenge_original
                q_enable.clone()
                    * is_first_valid_row.clone()
                    * (challenge_cur.clone() - challenge_original.clone()),
                // if cnt is not 0 and non-first row, then challenge_cur = challenge_prev*challenge_original
                q_enable.clone()
                    * is_valid_row.clone()
                    * (1.expr() - is_first_valid_row.clone())
                    * (challenge_cur.clone() - challenge_prev * challenge_original.clone()),
            ]);

            // random constrains
            for i in 0..NUM_RANDOM {
                // if it is not the first row, the random of the current row is equal to the random of the previous row
                constrains.push(
                    q_enable.clone()
                        * is_valid_row.clone()
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
                            * is_valid_row.clone()
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
            let length = meta.query_advice(config.length, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());

            let length_prev = meta.query_advice(config.length, Rotation::prev());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());

            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let is_valid_row = 1.expr() - cnt_is_zero;
            let is_last_valid_row = config.is_last_valid_row.expr();
            let is_first_valid_row = config.is_first_valid_row.expr();

            vec![
                // the cnt value is increasing, and the difference between every two rows of cnt is 1
                q_enable.clone() * is_valid_row.clone() * (cnt.clone() - cnt_prev - 1.expr()),
                // the rows before first_valid_row are all pdding rows(all values are 0)
                q_enable.clone() * is_first_valid_row.clone() * length_prev.clone(),
                // the values of length are the same
                q_enable.clone()
                    * is_valid_row
                    * (1.expr() - is_first_valid_row.clone())
                    * (length.clone() - length_prev),
                // the row where last_valid_row is located, the value of length is equal to cnt
                q_enable.clone() * is_last_valid_row * (length - cnt),
            ]
        });

        // rlc_acc constrains
        meta.create_gate("PUBLIC_RLC_ACC", |meta| {
            let challenge = challenges_expr.keccak_input();
            let q_enable = meta.query_selector(config.q_enable);
            let is_first_valid_row = config.is_first_valid_row.expr();
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let is_valid_row = 1.expr() - cnt_is_zero;

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
                        * is_valid_row.clone()
                        * (1.expr() - is_first_valid_row.clone())
                        * (rlc_acc_vec_cur[i].clone()
                            - rlc_acc_vec_prev[i].clone() * challenge.clone()
                            - values_u8_vec_cur[i].clone()),
                );
            }
            constrains
        });

        // todo fix 由于 CodeHash 的修改，这里暂时有点问题，在public哈希修改的时候再考虑修复这个地方
        // values u8 constrains
        // if tag != nil && tag != txCalldata && tag != txLogData, then src_value == target_value, for example, src_tag == target_tag, src_block_tx_idx == target_block_tx_idx ...
        //    target_tag = tag_u8.Rotation(-15)*2^120 + tag_u8.Rotation(-14)*2^112 + tag_u8.Rotation(-13)2^104 + tag_u8.Rotation(-12)*2^96 + ...tag_u8.Rotation(-1)*2^8 + tag_u8.Rotation::cur()
        // if tag != nil && (tag == txCallData || tag == txLogData) then, value1 == value1_u8 && value0_u8 == 0 && value2_u8 == 0 && value3_u8 == 0 && tag_u8 == 0 && block_tx_idx == 0
        // meta.create_gate("PUBLIC_U8_AND_VALUE", |meta| {
        //     let q_enable = meta.query_selector(config.q_enable);
        //     let tag = meta.query_advice(config.tag, Rotation::cur());
        //     let block_tx_idx = meta.query_advice(config.block_tx_idx, Rotation::cur());
        //     let value0 = meta.query_advice(config.values[0], Rotation::cur());
        //     let value1 = meta.query_advice(config.values[1], Rotation::cur());
        //     let value2 = meta.query_advice(config.values[2], Rotation::cur());
        //     let value3 = meta.query_advice(config.values[3], Rotation::cur());
        //
        //     let tag_is_nil = config.tag_is_nil.expr_at(meta, Rotation::cur());
        //     let tag_is_tx_calldata = config.tag_is_tx_calldata.expr_at(meta, Rotation::cur());
        //     let tag_is_tx_logdata = config.tag_is_tx_logdata.expr_at(meta, Rotation::cur());
        //     let data_idx_is_zero = config.value2_is_zero.expr_at(meta, Rotation::cur());
        //
        //     let tag_is_not_nil = 1.expr() - tag_is_nil.clone();
        //     let tag_is_not_tx_calldata = 1.expr() - tag_is_tx_calldata.clone();
        //     let tag_is_not_tx_logdata = 1.expr() - tag_is_tx_logdata.clone();
        //
        //     // tag | block_tx_idx | value0 | value1 | value2 | value3
        //     let src_value_vec = vec![tag, block_tx_idx, value0.clone(), value1, value2, value3];
        //
        //     // =================== calc target value ===================
        //     // get u8 expression
        //     // for example:
        //     //  tag_u8.Rotation(-15)
        //     //  tag_u8.Rotation(-14)
        //     //  tag_u8.Rotation(-13)
        //     //  ...
        //     //  tag_u8.Rotation(-1)
        //     //  tag_u8.Rotation::cur()
        //     let mut u8_vec_vec: Vec<Vec<Expression<F>>> = vec![vec![]; NUM_U8]; // [tag_u8_vec, block_tx_idx_u8_vec, value0_u8_vec, value2_u8_vec, value3_u8_vec] (Rotation::cur() ~ Rotation(-15))
        //     let mut u8_cur_vec = vec![]; // tag_u8_cur | block_tx_idx_u8_cur | value0_u8_cur | value1_u8_cur | value2_u8_cur | value3_u8_cur
        //     for i in 0..=NUM_ROTATION {
        //         // i:0, rotation=-(15-0)=-15
        //         // i:1, rotation=-(15-1)=-14
        //         // ...
        //         // i:15, rotation=-(15-15)=0 (Rotation::cur())
        //         let at = -(NUM_ROTATION as i32 - i as i32);
        //         for (i, u8_vec) in u8_vec_vec.iter_mut().enumerate() {
        //             let v_u8 = meta.query_advice(config.values_u8_vec[i], Rotation(at));
        //             if at == 0 {
        //                 u8_cur_vec.push(v_u8.clone());
        //             }
        //             u8_vec.push(v_u8);
        //         }
        //     }
        //
        //     // tag | block_tx_idx | value0 | value1 | value2 | value3
        //     // calc target_value(u8_vec is big endian)
        //     // for example:
        //     //  target_tag = tag_u8.Rotation(-15)*2^120 + tag_u8.Rotation(-14)*2^112 + tag_u8.Rotation(-13)2^104 + tag_u8.Rotation(-12)*2^96 + ...tag_u8.Rotation(-1)*2^8 + tag_u8.Rotation::cur()
        //     let mut target_value_vec = vec![];
        //     for u8_vec in u8_vec_vec {
        //         target_value_vec.push(expr_from_be_bytes(&u8_vec))
        //     }
        //
        //     // =================== constrains ===================
        //     let mut constrains = vec![];
        //     for i in 0..NUM_U8 {
        //         // if tag != nil && tag != txCalldata && tag != txLogData, then src_value=target_value
        //         constrains.push(
        //             q_enable.clone()
        //                 * tag_is_not_nil.clone()
        //                 * tag_is_not_tx_calldata.clone()
        //                 * tag_is_not_tx_logdata.clone()
        //                 * (target_value_vec[i].clone() - src_value_vec[i].clone()),
        //         );
        //
        //         // if tag != nil && (tag == txCallData || tag == txLogData) && data_idx == 0, then src_value=target_value
        //         constrains.push(
        //             q_enable.clone()
        //                 * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
        //                 * data_idx_is_zero.clone()
        //                 * (target_value_vec[i].clone() - src_value_vec[i].clone()),
        //         );
        //
        //         // tag == txCallData or tag == txLogData can already indicate tag!=nil
        //         if i == NUM_U8 - 1 {
        //             // if tag != nil && tag == txCallData || tag == txLogData && data_idx != 0 then value3 == value3_u8
        //             constrains.push(
        //                 q_enable.clone()
        //                     * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
        //                     * (1.expr() - data_idx_is_zero.clone())
        //                     * (u8_cur_vec[i].clone() - src_value_vec[i].clone()),
        //             );
        //         } else {
        //             // if tag != nil && (tag == txCallData || tag == txLogData) && idx != 0
        //             // then tag_u8 == 0 && block_tx_idx == 0 && value0_u8 == 0 && value1_u8 == 0 && value2_u8
        //             constrains.push(
        //                 q_enable.clone()
        //                     * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
        //                     * (1.expr() - data_idx_is_zero.clone())
        //                     * u8_cur_vec[i].clone(),
        //             );
        //         }
        //     }
        //
        //     constrains
        // });

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

            let tag_is_nil = config.tag_is_nil.expr_at(meta, Rotation::cur());
            let tag_is_tx_calldata = config.tag_is_tx_calldata.expr_at(meta, Rotation::cur());
            let tag_is_tx_logdata = config.tag_is_tx_logdata.expr_at(meta, Rotation::cur());

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
                    .tag_is_nil
                    .expr_at(meta, Rotation(-(rotation as i32)));
                constrains.push(
                    q_enable.clone()
                        * tag_is_not_nil.clone()
                        * tag_is_not_tx_calldata.clone()
                        * tag_is_not_tx_logdata.clone()
                        * (1.expr() - tag_is_nil_rotation),
                );
            }

            // if tag != nil && (tag == txCallData || tag == txLogData) && value2(idx_cur) != 0,
            // then value2_cur(idx_cur) == value2_prev+1 (idx_cur+1)
            //      tag_cur == tag_prev
            //      block_tx_idx_cur == block_tx_idx_prev
            //      value0 == value0_prev  (the value of value0 is log_index or zero)
            //      value1 == 0 (the value of value1 is zero)
            constrains.extend(vec![
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value2.clone() // there are only two cases for value2: 0 and non-0
                    * (value2.clone() - value2_prev - 1.expr()),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value2.clone()
                    * (tag.clone() - tag_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value2.clone()
                    * (block_tx_idx.clone() - block_tx_idx_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value2.clone()
                    * (value0.clone() - value0_prev),
                q_enable.clone()
                    * tag_is_not_nil.clone()
                    * (tag_is_tx_calldata.clone() + tag_is_tx_logdata.clone())
                    * value2.clone()
                    * value1.clone(),
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

        // hash constrains
        meta.create_gate("PUBLIC_HASH", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let hash_hi_cur = meta.query_advice(config.hash_hi, Rotation::cur());
            let hash_lo_cur = meta.query_advice(config.hash_lo, Rotation::cur());

            let hash_hi_prev = meta.query_advice(config.hash_hi, Rotation::prev());
            let hash_lo_prev = meta.query_advice(config.hash_lo, Rotation::prev());

            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let is_valid_row = 1.expr() - cnt_is_zero;
            let is_first_valid_row = config.is_first_valid_row.expr();

            vec![
                q_enable.clone()
                    * is_valid_row.clone()
                    * (1.expr() - is_first_valid_row.clone())
                    * (hash_hi_cur - hash_hi_prev),
                q_enable.clone()
                    * is_valid_row
                    * (1.expr() - is_first_valid_row.clone())
                    * (hash_lo_cur - hash_lo_prev),
            ]
        });

        #[cfg(not(feature = "no_public_hash_lookup"))]
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
        num_row_incl_padding: usize,
    ) -> Result<(Option<Cell>, Option<Cell>), Error> {
        let challenge = challenges.keccak_input();
        // assign begin padding row
        let default_random_vec = vec![Value::known(F::ZERO); NUM_RANDOM];
        let mut default_rlc_acc_vec_prev: Vec<Value<F>> = vec![Value::known(F::ZERO); NUM_RLC_ACC];
        let defatult_row = Row::default();
        for offset in 0..num_padding_begin {
            self.assign_row(
                region,
                offset,
                &witness.public[offset],
                &witness.public[offset + 1],
                Value::known(F::ZERO),
                &default_random_vec,
                &mut default_rlc_acc_vec_prev,
            )?;
            self.assign_challenge_row(region, offset, Value::known(F::ZERO))?;
        }

        // assign valid row

        // calc random, random = challenge^length
        // challenge, challenge^2, challenge^3, challenge^4...challenge^length
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

        // assign value to cell
        let public_valid_row_num = witness.public.len();
        let (mut hash_hi_cell, mut hash_lo_cell): (Option<Cell>, Option<Cell>) = (None, None);
        for offset in num_padding_begin..public_valid_row_num {
            let row_next = if offset == public_valid_row_num - 1 {
                &defatult_row
            } else {
                &witness.public[offset + 1]
            };
            // assign
            let (hash_hi, hash_lo) = self.assign_row(
                region,
                offset,
                &witness.public[offset],
                row_next,
                challenge,
                &random_vec,
                &mut rlc_acc_vec_prev,
            )?;

            if hash_hi.is_some() {
                hash_hi_cell = hash_hi;
                hash_lo_cell = hash_lo;
            }

            // assign challenge column
            self.assign_challenge_row(region, offset, challenge_vec[offset - num_padding_begin])?;
        }

        // assign padding row
        for offset in witness.public.len()..num_row_incl_padding {
            self.assign_row(
                region,
                offset,
                &defatult_row,
                &defatult_row,
                Value::known(F::ZERO),
                &default_random_vec,
                &mut default_rlc_acc_vec_prev,
            )?;
            self.assign_challenge_row(region, offset, Value::known(F::ZERO))?;
        }

        Ok((hash_hi_cell, hash_lo_cell))
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
        row_next: &Row,
        challenge: Value<F>,
        random_vec: &Vec<Value<F>>,
        rlc_acc_vec_prev: &mut Vec<Value<F>>,
    ) -> Result<(Option<Cell>, Option<Cell>), Error> {
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

        //let tag_binary = BinaryNumberChip::construct(self.tag_binary);
        let is_first_valid_row = IsZeroChip::construct(self.is_first_valid_row.clone());
        let is_last_valid_row = IsZeroChip::construct(self.is_last_valid_row.clone());

        let cnt_is_zero = IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let tag_is_nil = IsZeroWithRotationChip::construct(self.tag_is_nil.clone());
        let tag_is_tx_logdata = IsZeroWithRotationChip::construct(self.tag_is_tx_logdata.clone());
        let tag_is_tx_calldata = IsZeroWithRotationChip::construct(self.tag_is_tx_calldata.clone());

        let value2_is_zero = IsZeroWithRotationChip::construct(self.value2_is_zero.clone());

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
        // tag_binary.assign(region, offset, &row.tag)?;

        // assign cnt flag
        let cnt_v = F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt.unwrap_or_default()));
        let cnt_cur_is_zero = row.cnt.unwrap_or_default().is_zero() as u64;
        let cnt_next_is_zero = row_next.cnt.unwrap_or_default().is_zero() as u64;

        cnt_is_zero.assign(region, offset, Value::known(cnt_v))?;
        is_first_valid_row.assign(region, offset, Value::known(cnt_v - F::from(1)))?;
        is_last_valid_row.assign(
            region,
            offset,
            Value::known(F::from(cnt_next_is_zero) - F::from(cnt_cur_is_zero) - F::from(1)),
        )?;

        // assign tag flag
        let tag_v = F::from_uniform_bytes(&convert_u256_to_64_bytes(&U256::from(row.tag as u8)));
        let tag_is_nil_v = Value::known(tag_v - F::from((Tag::Nil as u8) as u64));
        let tag_is_tx_logdata_v = Value::known(tag_v - F::from((Tag::TxLogData as u8) as u64));
        let tag_is_tx_calldata_v = Value::known(tag_v - F::from((Tag::TxCalldata as u8) as u64));

        assign_advice_or_fixed_with_value(region, offset, tag_is_nil_v, self.tag_is_nil_val)?;
        assign_advice_or_fixed_with_value(
            region,
            offset,
            tag_is_tx_logdata_v,
            self.tag_is_tx_logdata_val,
        )?;
        assign_advice_or_fixed_with_value(
            region,
            offset,
            tag_is_tx_calldata_v,
            self.tag_is_tx_calldata_val,
        )?;

        tag_is_nil.assign(region, offset, tag_is_nil_v)?;
        tag_is_tx_logdata.assign(region, offset, tag_is_tx_logdata_v)?;
        tag_is_tx_calldata.assign(region, offset, tag_is_tx_calldata_v)?;

        // txLoadData idx or txCallData idx
        value2_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row.value_2.unwrap_or_default(),
            ))),
        )?;

        // assign hash
        let hash_hi_cell = assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.hash_hi.unwrap_or_default(),
            self.hash_hi,
        )?;

        let hash_lo_cell = assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.hash_lo.unwrap_or_default(),
            self.hash_lo,
        )?;

        if row.cnt.unwrap_or_default() == U256::one() {
            Ok((Some(hash_hi_cell), Some(hash_lo_cell)))
        } else {
            Ok((None, None))
        }
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
pub struct PublicCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for PublicCircuit<F, MAX_NUM_ROW> {
    type Config = PublicCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        PublicCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }
    // instance return vector of vector
    /// +------+
    /// | hash |
    fn instance(&self) -> Vec<Vec<F>> {
        self.witness.get_public_instance()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        // assign row and calc rlc_acc
        let (hash_hi_cell, hash_lo_cell) = layouter.assign_region(
            || "public circuit",
            |mut region| {
                // assign value to cell
                let (hash_hi_cell, hash_lo_cell) = config.assign_with_region(
                    &mut region,
                    challenges,
                    &self.witness,
                    num_padding_begin,
                    MAX_NUM_ROW,
                )?;
                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok((hash_hi_cell, hash_lo_cell))
            },
        )?;

        // set instance copy constraints
        layouter.constrain_instance(
            hash_hi_cell.unwrap(),
            config.instance_hash,
            INSTANCE_HASH_HI_ROW,
        )?;
        layouter.constrain_instance(
            hash_lo_cell.unwrap(),
            config.instance_hash,
            INSTANCE_HASH_LO_ROW,
        )?;
        Ok(())
    }

    fn unusable_rows() -> (usize, usize) {
        (PUBLIC_NUM_BEGINNING_PADDING_ROW, 1)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.public.len()
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

    const TEST_MAX_NUM_ROW: usize = 65477; // k=16
    #[derive(Clone, Default, Debug)]
    pub struct PublicTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub public_circuit: PublicCircuit<F, MAX_NUM_ROW>,
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
        type Params = ();

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
    #[cfg(feature = "evm")]
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
        prover.assert_satisfied();
    }
}
