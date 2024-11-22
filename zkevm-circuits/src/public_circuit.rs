// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{
    POSEIDON_HASH_BYTES_IN_FIELD, POSEIDON_PUBLIC_LOOKUP_NUM, PUBLIC_NUM_ALL_VALUE,
    PUBLIC_NUM_BEGINNING_PADDING_ROW, PUBLIC_NUM_VALUES, PUBLIC_NUM_VALUES_U8_ROW,
};
use crate::poseidon_circuit::HASH_BLOCK_STEP_SIZE;
use crate::table::{LookupEntry, PoseidonTable, PublicTable};
use crate::util::{
    assign_advice_or_fixed_with_u256, assign_advice_or_fixed_with_value, convert_u256_to_64_bytes,
    Challenges, SubCircuit, SubCircuitConfig,
};
use crate::witness::public::{Row, Tag};
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::{not, Expr};
use halo2_proofs::circuit::{Cell, Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector, VirtualCells,
};
use halo2_proofs::poly::Rotation;
use poseidon_circuit::HASHABLE_DOMAIN_SPEC;
use std::marker::PhantomData;

const INSTANCE_HASH_ROW: usize = 0;

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

    /// the row counter starts at 1 and increases automatically
    cnt: Column<Advice>,
    /// the total length of row
    length: Column<Advice>,

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

    /// [tag||block_tx_idx||values] is inputs
    pub poseidon_hash: Column<Advice>,
    /// 0-[tag, block_tx_idx], 1-[value_0, value_1], 2-[value_2, value_3] control length
    pub control_length: [Column<Advice>; POSEIDON_PUBLIC_LOOKUP_NUM],
    pub poseidon_table: PoseidonTable,
}

pub struct PublicCircuitConfigArgs {
    pub q_enable: Selector,
    // refer table.rs PublicTable
    pub public_table: PublicTable,
    pub poseidon_table: PoseidonTable,
    pub instance_hash: Column<Instance>,
}

impl<F: Field> SubCircuitConfig<F> for PublicCircuitConfig<F> {
    type ConfigArgs = PublicCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            public_table,
            instance_hash,
            poseidon_table,
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
        // define advice column
        let cnt = meta.advice_column();
        let length = meta.advice_column();
        let tag_is_nil_val = meta.advice_column();
        let tag_is_tx_logdata_val = meta.advice_column();
        let tag_is_tx_calldata_val = meta.advice_column();
        let poseidon_hash = meta.advice_column();
        let control_length = std::array::from_fn(|_| meta.advice_column());

        // define instance column
        meta.enable_equality(instance_hash);
        meta.enable_equality(poseidon_hash);

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
            cnt,
            length,
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
            poseidon_hash,
            poseidon_table,
            control_length,
        };

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
                q_enable.clone()
                    * is_valid_row.clone()
                    * (cnt.clone() - cnt_prev.clone() - 1.expr()),
                // the rows before first_valid_row are all pdding rows(all values are 0)
                q_enable.clone() * is_first_valid_row.clone() * length_prev.clone(),
                q_enable.clone() * is_first_valid_row.clone() * cnt_prev.clone(),
                // the values of length are the same
                q_enable.clone()
                    * is_valid_row
                    * (1.expr() - is_first_valid_row.clone())
                    * (length.clone() - length_prev),
                // the row where last_valid_row is located, the value of length is equal to cnt
                q_enable.clone() * is_last_valid_row * (length - cnt),
            ]
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

            let tag_is_nil = config.tag_is_nil.expr_at(meta, Rotation::cur());
            let tag_is_tx_calldata = config.tag_is_tx_calldata.expr_at(meta, Rotation::cur());
            let tag_is_tx_logdata = config.tag_is_tx_logdata.expr_at(meta, Rotation::cur());

            let tag_is_not_nil = 1.expr() - tag_is_nil.clone();

            let mut constrains = vec![];

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

        let all_value_num = PUBLIC_NUM_ALL_VALUE.expr();
        let hash_bytes_in_filed = POSEIDON_HASH_BYTES_IN_FIELD.expr();
        let hash_step = HASH_BLOCK_STEP_SIZE.expr();
        // hash constrains
        meta.create_gate("PUBLIC_HASH", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_valid_row = not::expr(config.cnt_is_zero.expr_at(meta, Rotation::cur()));
            let is_first_valid_row = config.is_first_valid_row.expr();
            let not_first_row = not::expr(is_first_valid_row.clone());
            let condition = q_enable * is_valid_row;

            let poseidon_hash = meta.query_advice(config.poseidon_hash, Rotation::cur());
            let poseidon_hash_prev = meta.query_advice(config.poseidon_hash, Rotation::prev());

            // control_length 满足第一行的control_length_0 = length * 6 * 31
            // control_length_0 - 62 = control_length_1
            // control_length_1 - 62 = control_length_2
            // control_length_2_prev - 62 = control_length_0
            let length = meta.query_advice(config.length, Rotation::cur());
            let control_length_0 = meta.query_advice(config.control_length[0], Rotation::cur());
            let control_length_1 = meta.query_advice(config.control_length[1], Rotation::cur());
            let control_length_2 = meta.query_advice(config.control_length[2], Rotation::cur());
            let control_length_2_prev =
                meta.query_advice(config.control_length[2], Rotation::prev());

            vec![
                condition.clone()
                    * is_first_valid_row.clone()
                    * (control_length_0.clone() - length * all_value_num * hash_bytes_in_filed),
                condition.clone()
                    * not_first_row.clone()
                    * (control_length_0.clone() - hash_step.clone() - control_length_1.clone()),
                condition.clone()
                    * not_first_row.clone()
                    * (control_length_1 - hash_step.clone() - control_length_2.clone()),
                condition.clone()
                    * not_first_row.clone()
                    * (control_length_2_prev - hash_step.clone() - control_length_0.clone()),
                condition.clone() * not_first_row.clone() * (poseidon_hash - poseidon_hash_prev),
            ]
        });

        config.poseidon_lookup(meta, "PUBLIC_LOOKUP_POSEIDON_HASH");
        config
    }
}

impl<F: Field> PublicCircuitConfig<F> {
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_padding_begin: usize,
        num_row_incl_padding: usize,
    ) -> Result<Option<Cell>, Error> {
        // assign begin padding row
        let defatult_row = Row::default();
        for offset in 0..num_padding_begin {
            self.assign_row(
                region,
                offset,
                &witness.public[offset],
                &witness.public[offset + 1],
            )?;
        }

        // assign value to cell
        let public_valid_row_num = witness.public.len();
        let mut poseidon_hash_cell: Option<Cell> = None;
        for offset in num_padding_begin..public_valid_row_num {
            let row_next = if offset == public_valid_row_num - 1 {
                &defatult_row
            } else {
                &witness.public[offset + 1]
            };
            // assign
            let poseidon_hash =
                self.assign_row(region, offset, &witness.public[offset], row_next)?;

            if poseidon_hash.is_some() {
                poseidon_hash_cell = poseidon_hash;
            }
        }

        // assign padding row
        for offset in witness.public.len()..num_row_incl_padding {
            self.assign_row(region, offset, &defatult_row, &defatult_row)?;
        }

        Ok(poseidon_hash_cell)
    }

    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
        row_next: &Row,
    ) -> Result<Option<Cell>, Error> {
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
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.control_length_0.unwrap_or_default(),
            self.control_length[0],
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.control_length_1.unwrap_or_default(),
            self.control_length[1],
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.control_length_2.unwrap_or_default(),
            self.control_length[2],
        )?;

        // assign cnt and length
        assign_advice_or_fixed_with_u256(region, offset, &row.cnt.unwrap_or_default(), self.cnt)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.length.unwrap_or_default(),
            self.length,
        )?;

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

        let poseidon_hash_cell = assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row.poseidon_hash.unwrap_or_default(),
            self.poseidon_hash,
        )?;

        if row.cnt.unwrap_or_default() == U256::one() {
            Ok(Some(poseidon_hash_cell))
        } else {
            Ok(None)
        }
    }

    /// set the annotation information of the circuit colum
    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "PUBLIC_tag", self.tag);
        region.name_column(|| "PUBLIC_block_tx_idx", self.block_tx_idx);

        for i in 0..PUBLIC_NUM_VALUES {
            region.name_column(|| format!("PUBLIC_value_{}", i), self.values[i]);
        }

        region.name_column(|| "PUBLIC_cnt", self.cnt);
        region.name_column(|| "PUBLIC_length", self.length);

        self.is_first_valid_row
            .annotate_columns_in_region(region, "PUBLIC_is_first_valid_row");
        self.is_last_valid_row
            .annotate_columns_in_region(region, "PUBLIC_is_last_valid_row");
        self.cnt_is_zero
            .annotate_columns_in_region(region, "PUBLIC_cnt_is_zero");

        region.name_column(|| "PUBLIC_tag_is_nil_val", self.tag_is_nil_val);
        region.name_column(
            || "PUBLIC_tag_is_tx_logdata_val",
            self.tag_is_tx_logdata_val,
        );
        region.name_column(
            || "PUBLIC_tag_is_tx_calldata_val",
            self.tag_is_tx_calldata_val,
        );

        self.tag_is_nil
            .annotate_columns_in_region(region, "PUBLIC_tag_is_nil");
        self.tag_is_tx_logdata
            .annotate_columns_in_region(region, "PUBLIC_tag_is_tx_logdata");
        self.tag_is_tx_calldata
            .annotate_columns_in_region(region, "PUBLIC_tag_is_tx_calldata");
        self.value2_is_zero
            .annotate_columns_in_region(region, "PUBLIC_value2_is_zero");

        region.name_column(|| "PUBLIC_poseidon_hash", self.poseidon_hash);

        for i in 0..POSEIDON_PUBLIC_LOOKUP_NUM {
            region.name_column(
                || format!("PUBLIC_control_length_{}", i),
                self.control_length[i],
            );
        }
    }

    pub fn poseidon_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        let inputs_fn = |meta: &mut VirtualCells<F>, i: usize| match i {
            0 => {
                let tag = meta.query_advice(self.tag, Rotation::cur());
                let block_idx = meta.query_advice(self.block_tx_idx, Rotation::cur());
                let control_length_0 = meta.query_advice(self.control_length[i], Rotation::cur());
                [tag, block_idx, control_length_0]
            }
            1 => {
                let value_0 = meta.query_advice(self.values[0], Rotation::cur());
                let value_1 = meta.query_advice(self.values[1], Rotation::cur());
                let control_length_1 = meta.query_advice(self.control_length[i], Rotation::cur());
                [value_0, value_1, control_length_1]
            }
            2 => {
                let value_2 = meta.query_advice(self.values[2], Rotation::cur());
                let value_3 = meta.query_advice(self.values[3], Rotation::cur());
                let control_length_2 = meta.query_advice(self.control_length[i], Rotation::cur());
                [value_2, value_3, control_length_2]
            }
            _ => panic!("not allowed index"),
        };
        let domain_spec_factor = Expression::Constant(F::from_u128(HASHABLE_DOMAIN_SPEC));

        for i in 0..POSEIDON_PUBLIC_LOOKUP_NUM {
            meta.lookup_any(name, |meta| {
                let q_enable = meta.query_selector(self.q_enable);
                let cnt_is_zero = self.cnt_is_zero.expr_at(meta, Rotation::cur());
                let is_valid_row = not::expr(cnt_is_zero);

                let hash = meta.query_advice(self.poseidon_hash, Rotation::cur());
                let inputs = inputs_fn(meta, i);
                let poseidon_entry = LookupEntry::Poseidon {
                    q_enable: 1.expr(),
                    hash_id: hash,
                    input_0: inputs[0].clone(),
                    input_1: inputs[1].clone(),
                    control: inputs[2].clone() * domain_spec_factor.clone(),
                    domain: 0.expr(),
                };

                let poseidon_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                    .poseidon_table
                    .get_lookup_vector(meta, poseidon_entry.clone());

                poseidon_lookup_vec
                    .into_iter()
                    .map(|(left, right)| (q_enable.clone() * is_valid_row.clone() * left, right))
                    .collect()
            });
        }
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
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        // assign row and calc rlc_acc
        let poseidon_hash_cell = layouter.assign_region(
            || "public circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);

                // assign value to cell
                let poseidon_hash_cell = config.assign_with_region(
                    &mut region,
                    &self.witness,
                    num_padding_begin,
                    MAX_NUM_ROW,
                )?;
                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(poseidon_hash_cell)
            },
        )?;

        // set instance copy constraints
        layouter.constrain_instance(
            poseidon_hash_cell.unwrap(),
            config.instance_hash,
            INSTANCE_HASH_ROW,
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
    use crate::poseidon_circuit::{
        PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs,
    };
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
        pub poseidon_circuit: PoseidonCircuit<F, MAX_NUM_ROW>,
    }

    #[derive(Clone)]
    pub struct PublicTestCircuitConfig<F: Field> {
        pub public_circuit: PublicCircuitConfig<F>,
        pub tag: Column<Advice>,
        pub block_tx_idx: Column<Advice>,
        pub values: [Column<Advice>; PUBLIC_NUM_VALUES],
        pub challenges: Challenges,
        pub poseidon_circuit: PoseidonCircuitConfig<F>,
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
            // construct poseidon table
            let poseidon_table = PoseidonTable::construct(meta);

            let challenges = Challenges::construct(meta);
            let public_circuit = PublicCircuitConfig::new(
                meta,
                PublicCircuitConfigArgs {
                    q_enable: q_enable_public,
                    public_table,
                    instance_hash,
                    poseidon_table,
                },
            );

            let poseidon_circuit =
                PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table });

            let config = PublicTestCircuitConfig {
                public_circuit,
                tag: meta.advice_column(),
                block_tx_idx: meta.advice_column(),
                values: std::array::from_fn(|_| meta.advice_column()),
                challenges,
                poseidon_circuit,
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

            self.poseidon_circuit.synthesize_sub(
                &config.poseidon_circuit,
                &mut layouter,
                &challenges
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
                public_circuit: PublicCircuit::new_from_witness(&witness),
                poseidon_circuit: PoseidonCircuit::new_from_witness(&witness),
            }
        }

        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.public_circuit.instance());
            vec.extend(self.poseidon_circuit.instance());
            vec
        }
    }

    fn test_public_circuit(witness: Witness) -> MockProver<Fp> {
        // ceiling of log2(MAX_NUM_ROW)
        let k = log2_ceil(TEST_MAX_NUM_ROW);
        let circuit = PublicTestCircuit::<Fp, TEST_MAX_NUM_ROW>::new(witness.clone());
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
