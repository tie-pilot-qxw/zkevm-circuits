use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{BytecodeTable, FixedTable, LookupEntry, PublicTable, StateTable};

use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::copy::{Row, Tag};
use crate::witness::{public, state, Witness};
use eth_types::Field;

use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::circuit::{Layouter, Region, Value};

use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CopyCircuitConfig<F: Field> {
    pub q_enable: Selector,
    /// The byte value that is copied
    pub byte: Column<Advice>,
    /// The source id, tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: Column<Advice>,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: Column<Advice>,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: Column<Advice>,
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
    /// The accumulation value of bytes for one copy operation
    pub acc: Column<Advice>,
    /// IsZero chip for column len
    pub len_is_zero: IsZeroWithRotationConfig<F>,
    /// IsZero chip for column cnt
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// IsZero chip for len-cnt-1
    pub len_sub_cnt_one_is_zero: IsZeroConfig<F>,
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// src Tag of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    pub src_tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// dst Tag of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    pub dst_tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    // Tables used for lookup
    bytecode_table: BytecodeTable<F>,
    state_table: StateTable,
    // add public_table
    public_table: PublicTable,
}

pub struct CopyCircuitConfigArgs<F> {
    pub bytecode_table: BytecodeTable<F>,
    pub state_table: StateTable,
    pub public_table: PublicTable,
}

impl<F: Field> SubCircuitConfig<F> for CopyCircuitConfig<F> {
    type ConfigArgs = CopyCircuitConfigArgs<F>;
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            bytecode_table,
            state_table,
            public_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let byte = meta.advice_column();
        let src_id = meta.advice_column();
        let src_pointer = meta.advice_column();
        let src_stamp = meta.advice_column();
        let dst_id = meta.advice_column();
        let dst_pointer = meta.advice_column();
        let dst_stamp = meta.advice_column();
        let cnt = meta.advice_column();
        let len = meta.advice_column();
        let acc = meta.advice_column();

        let len_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), len);
        let cnt_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), cnt);

        let _len_sub_cnt_one_is_zero_inv = meta.advice_column();
        let len_sub_cnt_one_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let len = meta.query_advice(len, Rotation::cur());
                let cnt = meta.query_advice(cnt, Rotation::cur());
                len - cnt - 1.expr()
            },
            _len_sub_cnt_one_is_zero_inv,
        );

        let src_tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let dst_tag = BinaryNumberChip::configure(meta, q_enable.clone(), None);
        let config = Self {
            q_enable,
            byte,
            src_id,
            src_pointer,
            src_stamp,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            src_tag,
            dst_tag,
            bytecode_table,
            state_table,
            public_table,
            len_is_zero,
            cnt_is_zero,
            len_sub_cnt_one_is_zero,
            acc,
        };

        meta.create_gate("COPY", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let src_tag = config.src_tag.value(Rotation::cur())(meta);
            let src_id = meta.query_advice(config.src_id, Rotation::cur());
            let src_pointer = meta.query_advice(config.src_pointer, Rotation::cur());
            let src_stamp = meta.query_advice(config.src_stamp, Rotation::cur());
            let dst_tag = config.dst_tag.value(Rotation::cur())(meta);
            let dst_id = meta.query_advice(config.dst_id, Rotation::cur());
            let dst_pointer = meta.query_advice(config.dst_pointer, Rotation::cur());
            let dst_stamp = meta.query_advice(config.dst_stamp, Rotation::cur());
            let len = meta.query_advice(config.len, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let byte = meta.query_advice(config.byte, Rotation::cur());
            let acc = meta.query_advice(config.acc, Rotation::cur());
            let acc_prev = meta.query_advice(config.acc, Rotation::prev());

            let next_src_tag = config.src_tag.value(Rotation::next())(meta);
            let next_src_id = meta.query_advice(config.src_id, Rotation::next());
            let next_src_pointer = meta.query_advice(config.src_pointer, Rotation::next());
            let next_src_stamp = meta.query_advice(config.src_stamp, Rotation::next());
            let next_dst_tag = config.dst_tag.value(Rotation::next())(meta);
            let next_dst_id = meta.query_advice(config.dst_id, Rotation::next());
            let next_dst_pointer = meta.query_advice(config.dst_pointer, Rotation::next());
            let next_dst_stamp = meta.query_advice(config.dst_stamp, Rotation::next());
            let next_cnt = meta.query_advice(config.cnt, Rotation::next());
            let next_len = meta.query_advice(config.len, Rotation::next());

            let len_is_zero = config.len_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let len_sub_cnt_one_is_zero = config.len_sub_cnt_one_is_zero.expr();

            // len==0 --> next_cnt==0
            // len-cnt-1==0 --> next_cnt==0
            let mut constraints = vec![
                (
                    "len_is_zero => next_cnt_is_zero",
                    q_enable.clone() * len_is_zero.clone() * next_cnt.clone(),
                ),
                (
                    "len_sub_cnt_one_is_zero => next_cnt=0",
                    q_enable.clone() * len_sub_cnt_one_is_zero.clone() * next_cnt.clone(),
                ),
            ];

            let is_not_zero_exp =
                (1.expr() - len_is_zero.clone()) * (1.expr() - len_sub_cnt_one_is_zero.clone());
            constraints.extend(vec![
                // len!=0 && len-cnt-1!=0 --> next_cnt=cnt+1
                (
                    "len !=0 and len-cnt-1!=0 => next_cnt=cnt+1",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_cnt - cnt.clone() - 1.expr()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_len=cur_len",
                    q_enable.clone() * is_not_zero_exp.clone() * (next_len - len.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_src_tag=cur_src_tag",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_src_tag.clone() - src_tag.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_src_id=cur_src_id",
                    q_enable.clone() * is_not_zero_exp.clone() * (next_src_id - src_id.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_src_pointer=cur_src_pointer",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_src_pointer - src_pointer.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_src_stamp=cur_src_stamp",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_src_stamp - src_stamp.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_dst_tag=cur_dst_tag",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_dst_tag.clone() - dst_tag.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_dst_id=cur_dst_id",
                    q_enable.clone() * is_not_zero_exp.clone() * (next_dst_id - dst_id.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_dst_pointer=cur_dst_pointer",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_dst_pointer - dst_pointer.clone()),
                ),
                (
                    "len !=0 and len-cnt-1!=0 => next_dst_stamp=cur_dst_stamp",
                    q_enable.clone()
                        * is_not_zero_exp.clone()
                        * (next_dst_stamp - dst_stamp.clone()),
                ),
            ]);

            // len=0 ---> all field is zero
            constraints.extend(vec![(
                "len=0 => src_tag=0",
                q_enable.clone() * len_is_zero.clone() * src_tag.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => src_id=0",
                q_enable.clone() * len_is_zero.clone() * src_id.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => src_pointer=0",
                q_enable.clone() * len_is_zero.clone() * src_pointer.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => src_stamp=0",
                q_enable.clone() * len_is_zero.clone() * src_stamp.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => dst_tag=0",
                q_enable.clone() * len_is_zero.clone() * dst_tag.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => dst_id=0",
                q_enable.clone() * len_is_zero.clone() * dst_id.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => dst_pointer=0",
                q_enable.clone() * len_is_zero.clone() * dst_pointer.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => dst_stamp=0",
                q_enable.clone() * len_is_zero.clone() * dst_stamp.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => cnt=0",
                q_enable.clone() * len_is_zero.clone() * cnt.clone(),
            )]);

            // src_type=ZERO ---> src_id、src_pointer、src_stamp is 0
            let src_tag_is_zero = config.src_tag.value_equals(Tag::Zero, Rotation::cur())(meta);
            constraints.extend(vec![
                (
                    "src_type=ZERO => byte=0",
                    q_enable.clone() * src_tag_is_zero.clone() * byte.clone(),
                ),
                (
                    "src_type=ZERO => src_id=0",
                    q_enable.clone() * src_tag_is_zero.clone() * src_id.clone(),
                ),
                (
                    "src_type=ZERO => src_pointer=0",
                    q_enable.clone() * src_tag_is_zero.clone() * src_pointer.clone(),
                ),
                (
                    "src_type=ZERO => src_stamp=0",
                    q_enable.clone() * src_tag_is_zero.clone() * src_stamp.clone(),
                ),
            ]);

            // dst_type=ZERO ---> dst_id、dst_pointer、dst_stamp is 0
            let dst_tag_is_zero = config.dst_tag.value_equals(Tag::Zero, Rotation::cur())(meta);
            constraints.extend(vec![
                (
                    "dst_type=ZERO => byte=0",
                    q_enable.clone() * dst_tag_is_zero.clone() * byte.clone(),
                ),
                (
                    "dst_type=ZERO => dst_id=0",
                    q_enable.clone() * dst_tag_is_zero.clone() * dst_id.clone(),
                ),
                (
                    "dst_type=ZERO => dst_pointer=0",
                    q_enable.clone() * dst_tag_is_zero.clone() * dst_pointer.clone(),
                ),
                (
                    "dst_type=ZERO => dst_stamp=0",
                    q_enable.clone() * dst_tag_is_zero.clone() * dst_stamp.clone(),
                ),
            ]);

            // src_type=Null ---> src_id、src_pointer、src_stamp is 0
            let src_tag_is_null = config.src_tag.value_equals(Tag::Null, Rotation::cur())(meta);
            constraints.extend(vec![
                (
                    "src_type=Null => src_id=0",
                    q_enable.clone() * src_tag_is_null.clone() * src_id.clone(),
                ),
                (
                    "src_type=Null => src_pointer=0",
                    q_enable.clone() * src_tag_is_null.clone() * src_pointer.clone(),
                ),
                (
                    "src_type=Null => src_stamp=0",
                    q_enable.clone() * src_tag_is_null.clone() * src_stamp.clone(),
                ),
            ]);

            // dst_type=Null ---> dst_id、dst_pointer、dst_stamp is 0
            let dst_tag_is_null = config.dst_tag.value_equals(Tag::Null, Rotation::cur())(meta);
            constraints.extend(vec![
                (
                    "dst_type=Null => dst_id=0",
                    q_enable.clone() * dst_tag_is_null.clone() * dst_id.clone(),
                ),
                (
                    "dst_type=Null => dst_pointer=0",
                    q_enable.clone() * dst_tag_is_null.clone() * dst_pointer.clone(),
                ),
                (
                    "dst_type=Null => dst_stamp=0",
                    q_enable.clone() * dst_tag_is_null.clone() * dst_stamp.clone(),
                ),
            ]);

            // cnt=0 ---> acc=byte
            constraints.extend(vec![(
                "cnt=0 => acc=byte",
                q_enable.clone() * cnt_is_zero.clone() * (acc.clone() - byte.clone()),
            )]);

            // cnt!=0 ---> acc=byte+acc_prev*(2^8)
            constraints.extend(vec![(
                "cnt!=0 => acc=acc_pre*256+acc",
                q_enable.clone()
                    * (1.expr() - cnt_is_zero)
                    * (acc - (byte + acc_prev * 256.expr())),
            )]);

            constraints
        });

        // lookups
        // src bytecode lookup
        config.src_bytecode_lookup(meta, "COPY_src_bytecode_lookup");
        // src memory lookup
        config.src_state_lookup(
            meta,
            "COPY_src_memory_lookup",
            Tag::Memory,
            state::Tag::Memory,
        );
        // src call-data lookup
        config.src_state_lookup(
            meta,
            "COPY_src_call-data_lookup",
            Tag::Calldata,
            state::Tag::CallData,
        );
        // src return-data lookup
        config.src_state_lookup(
            meta,
            "COPY_src_return-data_lookup",
            Tag::Returndata,
            state::Tag::ReturnData,
        );
        // src public-calldata lookup
        config.src_public_calldata_lookup(
            meta,
            "COPY_src_public-calldata_lookup",
            Tag::PublicCalldata,
            public::Tag::TxCalldata,
        );
        // dst memory lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_memory_lookup",
            Tag::Memory,
            state::Tag::Memory,
        );
        // dst call-data lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_call-data_lookup",
            Tag::Calldata,
            state::Tag::CallData,
        );
        // dst return-data lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_return-data_lookup",
            Tag::Returndata,
            state::Tag::ReturnData,
        );
        // dst public-log lookup
        config.dst_public_log_lookup(
            meta,
            "COPY_dst_log_lookup",
            Tag::PublicLog,
            public::Tag::TxLog,
        );
        config
    }
}

impl<F: Field> CopyCircuitConfig<F> {
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
    ) -> Result<(), Error> {
        let len_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.len_is_zero.clone());
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let len_sub_cnt_one_is_zero = IsZeroChip::construct(self.len_sub_cnt_one_is_zero.clone());

        assign_advice_or_fixed(region, offset, &row.byte, self.byte)?;
        assign_advice_or_fixed(region, offset, &row.src_id, self.src_id)?;
        assign_advice_or_fixed(region, offset, &row.src_pointer, self.src_pointer)?;
        assign_advice_or_fixed(region, offset, &row.src_stamp, self.src_stamp)?;
        assign_advice_or_fixed(region, offset, &row.dst_id, self.dst_id)?;
        assign_advice_or_fixed(region, offset, &row.dst_pointer, self.dst_pointer)?;
        assign_advice_or_fixed(region, offset, &row.dst_stamp, self.dst_stamp)?;
        assign_advice_or_fixed(region, offset, &row.cnt, self.cnt)?;
        assign_advice_or_fixed(region, offset, &row.len, self.len)?;
        assign_advice_or_fixed(region, offset, &row.acc, self.acc)?;

        len_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.len))),
        )?;

        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt))),
        )?;

        // calc inv for len-cnt-1
        let len_val = F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.len));
        let cnt_val = F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.cnt));
        len_sub_cnt_one_is_zero.assign(region, offset, Value::known(len_val - cnt_val - F::ONE))?;

        let src_tag: BinaryNumberChip<F, Tag, LOG_NUM_STATE_TAG> =
            BinaryNumberChip::construct(self.src_tag);
        src_tag.assign(region, offset, &row.src_type)?;
        let dst_tag: BinaryNumberChip<F, Tag, LOG_NUM_STATE_TAG> =
            BinaryNumberChip::construct(self.dst_tag);
        dst_tag.assign(region, offset, &row.dst_type)?;
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
        for (offset, row) in witness.copy.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }

        // pad the rest rows
        for offset in witness.copy.len()..num_row_incl_padding {
            self.assign_row(region, offset, &Default::default())?;
        }
        Ok(())
    }

    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "COPY_byte", self.byte);
        region.name_column(|| "COPY_src_id", self.src_id);
        region.name_column(|| "COPY_src_pointer", self.src_pointer);
        region.name_column(|| "COPY_src_stamp", self.src_stamp);
        region.name_column(|| "COPY_dst_id", self.dst_id);
        region.name_column(|| "COPY_dst_pointer", self.dst_pointer);
        region.name_column(|| "COPY_dst_stamp", self.dst_stamp);
        region.name_column(|| "COPY_cnt", self.cnt);
        region.name_column(|| "COPY_len", self.len);
        region.name_column(|| "COPY_acc", self.acc);
        self.src_tag
            .annotate_columns_in_region(region, "COPY_src_tag");
        self.dst_tag
            .annotate_columns_in_region(region, "COPY_dst_tag");
        self.len_is_zero
            .annotate_columns_in_region(region, "COPY_len_is_zero");
        self.cnt_is_zero
            .annotate_columns_in_region(region, "COPY_cnt_is_zero");
        self.len_sub_cnt_one_is_zero
            .annotate_columns_in_region(region, "COPY_len_sub_cnt_one_is_zero");
    }

    /// bytecode src lookup
    pub fn src_bytecode_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        meta.lookup_any(name, |meta| {
            let byte_code_entry = LookupEntry::Bytecode {
                addr: meta.query_advice(self.src_id, Rotation::cur()),
                pc: meta.query_advice(self.src_pointer, Rotation::cur())
                    + meta.query_advice(self.cnt, Rotation::cur()),
                opcode: meta.query_advice(self.byte, Rotation::cur()),
            };
            let byte_code_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .bytecode_table
                .get_lookup_vector(meta, byte_code_entry.clone());
            byte_code_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let bytecode_enable =
                        self.src_tag.value_equals(Tag::Bytecode, Rotation::cur())(meta);
                    (q_enable * bytecode_enable * left, right)
                })
                .collect()
        });
    }

    /// state src lookup
    pub fn src_state_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &str,
        copy_type: Tag,
        state_tag: state::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let state_entry = LookupEntry::State {
                tag: (state_tag as u8).expr(),
                stamp: meta.query_advice(self.src_stamp, Rotation::cur())
                    + meta.query_advice(self.cnt, Rotation::cur()),
                value_hi: 0.expr(),
                value_lo: meta.query_advice(self.byte, Rotation::cur()),
                call_id_contract_addr: meta.query_advice(self.src_id, Rotation::cur()),
                pointer_hi: 0.expr(),
                pointer_lo: meta.query_advice(self.src_pointer, Rotation::cur())
                    + meta.query_advice(self.cnt, Rotation::cur()),
                is_write: 0.expr(),
            };
            let state_lookup_vec = self
                .state_table
                .get_lookup_vector(meta, state_entry.clone());
            state_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let state_enable = self.src_tag.value_equals(copy_type, Rotation::cur())(meta);
                    (q_enable * state_enable * left, right)
                })
                .collect()
        });
    }

    /// publicCallData src lookup
    pub fn src_public_calldata_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &str,
        copy_type: Tag,
        public_tag: public::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let public_entry = LookupEntry::Public {
                tag: (public_tag as u8).expr(),
                tx_idx_or_number_diff: meta.query_advice(self.src_id, Rotation::cur()),
                values: [
                    meta.query_advice(self.src_pointer, Rotation::cur())
                        + meta.query_advice(self.cnt, Rotation::cur()),
                    meta.query_advice(self.byte, Rotation::cur()),
                    0.expr(),
                    0.expr(),
                ],
            };
            let public_lookup_vec = self
                .public_table
                .get_lookup_vector(meta, public_entry.clone());
            public_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let public_enable = self.src_tag.value_equals(copy_type, Rotation::cur())(meta);
                    (q_enable * public_enable * left, right)
                })
                .collect()
        });
    }

    /// publicLog dst lookup
    pub fn dst_public_log_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &str,
        copy_type: Tag,
        public_tag: public::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let public_entry = LookupEntry::Public {
                tag: (public_tag as u8).expr(),
                tx_idx_or_number_diff: meta.query_advice(self.dst_id, Rotation::cur()),
                values: [
                    meta.query_advice(self.dst_stamp, Rotation::cur()),
                    (public::LogTag::Data as u8).expr(),
                    meta.query_advice(self.byte, Rotation::cur()),
                    meta.query_advice(self.src_pointer, Rotation::cur())
                        + meta.query_advice(self.cnt, Rotation::cur()),
                ],
            };
            let public_lookup_vec = self
                .public_table
                .get_lookup_vector(meta, public_entry.clone());
            public_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let public_enable = self.src_tag.value_equals(copy_type, Rotation::cur())(meta);
                    (q_enable * public_enable * left, right)
                })
                .collect()
        });
    }

    /// state dst lookup
    pub fn dst_state_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &str,
        copy_type: Tag,
        state_tag: state::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let state_entry = LookupEntry::State {
                tag: (state_tag as u8).expr(),
                stamp: meta.query_advice(self.dst_stamp, Rotation::cur())
                    + meta.query_advice(self.cnt, Rotation::cur()),
                value_hi: 0.expr(),
                value_lo: meta.query_advice(self.byte, Rotation::cur()),
                call_id_contract_addr: meta.query_advice(self.dst_id, Rotation::cur()),
                pointer_hi: 0.expr(),
                pointer_lo: meta.query_advice(self.dst_pointer, Rotation::cur())
                    + meta.query_advice(self.cnt, Rotation::cur()),
                is_write: 1.expr(),
            };
            let state_lookup_vec = self.state_table.get_lookup_vector(meta, state_entry);
            state_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(self.q_enable);
                    let state_enable = self.dst_tag.value_equals(copy_type, Rotation::cur())(meta);
                    (q_enable * state_enable * left, right)
                })
                .collect()
        });
    }
}

#[derive(Clone, Default, Debug)]
pub struct CopyCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for CopyCircuit<F, MAX_NUM_ROW> {
    type Config = CopyCircuitConfig<F>;
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
        (1, 1)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.copy.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bytecode_circuit::{
        BytecodeCircuit, BytecodeCircuitConfig, BytecodeCircuitConfigArgs,
    };
    use crate::constant::{MAX_CODESIZE, MAX_NUM_ROW};
    use crate::copy_circuit::CopyCircuit;
    use crate::public_circuit::{PublicCircuit, PublicCircuitConfig, PublicCircuitConfigArgs};
    use crate::state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs};
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct CopyTestCircuitConfig<F: Field> {
        pub bytecode_circuit: BytecodeCircuitConfig<F>,
        pub public_circuit: PublicCircuitConfig,
        pub copy_circuit: CopyCircuitConfig<F>,
        pub state_circuit: StateCircuitConfig<F>,
    }

    impl<F: Field> SubCircuitConfig<F> for CopyTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let (instance_addr, instance_bytecode) =
                BytecodeTable::construct_addr_bytecode_instance_column(meta);
            let q_enable_state = meta.complex_selector();
            let state_table = StateTable::construct(meta, q_enable_state);
            let public_table = PublicTable::construct(meta);
            let fixed_table = FixedTable::construct(meta);
            let bytecode_circuit = BytecodeCircuitConfig::new(
                meta,
                BytecodeCircuitConfigArgs {
                    q_enable: q_enable_bytecode,
                    bytecode_table,
                    instance_addr,
                    instance_bytecode,
                },
            );
            let state_circuit = StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    q_enable: q_enable_state,
                    state_table,
                    fixed_table,
                },
            );
            let public_circuit =
                PublicCircuitConfig::new(meta, PublicCircuitConfigArgs { public_table });

            let copy_circuit = CopyCircuitConfig::new(
                meta,
                CopyCircuitConfigArgs {
                    bytecode_table,
                    state_table,
                    public_table,
                },
            );
            CopyTestCircuitConfig {
                bytecode_circuit,
                public_circuit,
                copy_circuit,
                state_circuit,
            }
        }
    }

    #[derive(Clone, Default, Debug)]
    pub struct CopyTestCircuit<F: Field, const MAX_CODESIZE: usize> {
        pub copy_circuit: CopyCircuit<F, MAX_NUM_ROW>,
        pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW, MAX_CODESIZE>,
        pub state_circuit: StateCircuit<F, MAX_NUM_ROW>,
        pub public_circuit: PublicCircuit<F>,
    }

    impl<F: Field, const MAX_CODESIZE: usize> Circuit<F> for CopyTestCircuit<F, MAX_CODESIZE> {
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
            self.bytecode_circuit
                .synthesize_sub(&config.bytecode_circuit, &mut layouter)?;
            self.public_circuit
                .synthesize_sub(&config.public_circuit, &mut layouter)?;
            self.copy_circuit
                .synthesize_sub(&config.copy_circuit, &mut layouter)?;
            self.state_circuit
                .synthesize_sub(&config.state_circuit, &mut layouter)
        }
    }

    impl<F: Field, const MAX_CODESIZE: usize> CopyTestCircuit<F, MAX_CODESIZE> {
        pub fn new(witness: Witness) -> Self {
            Self {
                bytecode_circuit: BytecodeCircuit::new_from_witness(&witness),
                public_circuit: PublicCircuit::new_from_witness(&witness),
                copy_circuit: CopyCircuit::new_from_witness(&witness),
                state_circuit: StateCircuit::new_from_witness(&witness),
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bytecode_circuit.instance());
            vec.extend(self.public_circuit.instance());
            vec
        }
    }

    fn test_simple_copy_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CopyTestCircuit::<Fp, MAX_CODESIZE>::new(witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    #[test]
    fn test_core_parser() {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code);
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        let prover = test_simple_copy_circuit(witness);
        prover.assert_satisfied_par();
    }
}
