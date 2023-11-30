use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{BytecodeTable, LookupEntry, PublicTable, StateTable};

use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes};
use crate::util::{SubCircuit, SubCircuitConfig};
use crate::witness::copy::{Row, Type};
use crate::witness::{public, state, Witness};
use eth_types::{Field, U256};

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
    /// IsZero chip for column len
    pub len_is_zero: IsZeroWithRotationConfig<F>,
    /// IsZero chip for column cnt
    pub cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// IsZero chip for len-cnt-1
    pub len_sub_cnt_one_is_zero: IsZeroConfig<F>,
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// src Type of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    src_tag: BinaryNumberConfig<Type, LOG_NUM_STATE_TAG>,
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    /// dst Type of Zero,Memory,Calldata,Returndata,PublicLog,PublicCalldata,Bytecode
    dst_tag: BinaryNumberConfig<Type, LOG_NUM_STATE_TAG>,
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
            let next_cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::next());
            let len_sub_cnt_one_is_zero = config.len_sub_cnt_one_is_zero.expr();

            // len==0 --> next_cnt==0
            // len-cnt-1==0 --> next_cnt==0
            let mut constraints = vec![
                (
                    "len_is_zero, next_cnt_is_zero",
                    q_enable.clone() * len_is_zero.clone() * next_cnt.clone(),
                ),
                (
                    "len_sub_cnt_one_is_zero, next_cnt_is_zero",
                    q_enable.clone() * len_sub_cnt_one_is_zero.expr() * next_cnt.clone(),
                ),
            ];

            let is_not_zero_exp =
                (1.expr() - len_is_zero.clone()) * (1.expr() - len_sub_cnt_one_is_zero.expr());
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
                q_enable.clone() * len_is_zero.clone() * src_id,
            )]);
            constraints.extend(vec![(
                "len=0 => src_pointer=0",
                q_enable.clone() * len_is_zero.clone() * src_pointer,
            )]);
            constraints.extend(vec![(
                "len=0 => src_stamp=0",
                q_enable.clone() * len_is_zero.clone() * src_stamp,
            )]);
            constraints.extend(vec![(
                "len=0 => dst_tag=0",
                q_enable.clone() * len_is_zero.clone() * dst_tag.clone(),
            )]);
            constraints.extend(vec![(
                "len=0 => dst_id=0",
                q_enable.clone() * len_is_zero.clone() * dst_id,
            )]);
            constraints.extend(vec![(
                "len=0 => dst_pointer=0",
                q_enable.clone() * len_is_zero.clone() * dst_pointer,
            )]);
            constraints.extend(vec![(
                "len=0 => dst_stamp=0",
                q_enable.clone() * len_is_zero.clone() * dst_stamp,
            )]);
            constraints.extend(vec![(
                "len=0 => cnt=0",
                q_enable.clone() * len_is_zero.clone() * cnt,
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
            Type::Memory,
            state::Tag::Memory,
        );
        // src call-data lookup
        config.src_state_lookup(
            meta,
            "COPY_src_call-data_lookup",
            Type::Calldata,
            state::Tag::CallData,
        );
        // src return-data lookup
        config.src_state_lookup(
            meta,
            "COPY_src_return-data_lookup",
            Type::Returndata,
            state::Tag::ReturnData,
        );
        // src public-calldata lookup
        config.src_public_calldata_lookup(
            meta,
            "COPY_src_public-calldata_lookup",
            Type::PublicCalldata,
            public::Tag::TxCalldata,
        );
        // dst memory lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_memory_lookup",
            Type::Memory,
            state::Tag::Memory,
        );
        // dst call-data lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_call-data_lookup",
            Type::Calldata,
            state::Tag::CallData,
        );
        // dst return-data lookup
        config.dst_state_lookup(
            meta,
            "COPY_dst_return-data_lookup",
            Type::Returndata,
            state::Tag::ReturnData,
        );
        // dst public-log lookup
        config.dst_public_log_lookup(
            meta,
            "COPY_dst_log_lookup",
            Type::PublicLog,
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

        let src_tag: BinaryNumberChip<F, Type, 4> = BinaryNumberChip::construct(self.src_tag);
        src_tag.assign(region, offset, &row.src_type)?;
        let dst_tag: BinaryNumberChip<F, Type, 4> = BinaryNumberChip::construct(self.dst_tag);
        dst_tag.assign(region, offset, &row.dst_type)?;
        Ok(())
    }

    // assign a padding row whose state selector is the first `ExecutionState`
    // and auxiliary columns are kept from the last row
    fn assign_padding_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        let len_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.len_is_zero.clone());
        let cnt_is_zero: IsZeroWithRotationChip<F> =
            IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let len_sub_cnt_one_is_zero = IsZeroChip::construct(self.len_sub_cnt_one_is_zero.clone());

        //let len_sub_cnt_one_is_zero = IsZeroChip::construct(self.len_sub_cnt_one_is_zero.clone());
        assign_advice_or_fixed(region, offset, &U256::zero(), self.byte)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_pointer)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.src_stamp)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_id)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_pointer)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.dst_stamp)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.cnt)?;
        assign_advice_or_fixed(region, offset, &U256::zero(), self.len)?;

        len_is_zero.assign(region, offset, Value::known(F::ZERO))?;
        cnt_is_zero.assign(region, offset, Value::known(F::ZERO))?;
        len_sub_cnt_one_is_zero.assign(region, offset, Value::known(F::from(0) - F::from(1)))?;

        let src_tag: BinaryNumberChip<F, Type, 4> = BinaryNumberChip::construct(self.src_tag);
        src_tag.assign(region, offset, &Type::default())?;
        let dst_tag: BinaryNumberChip<F, Type, 4> = BinaryNumberChip::construct(self.dst_tag);
        dst_tag.assign(region, offset, &Type::default())?;
        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        for (offset, row) in witness.copy.iter().enumerate() {
            self.assign_row(region, offset, row)?;
        }
        // pad the rest rows
        for offset in witness.copy.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset)?;
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
                        self.src_tag.value_equals(Type::Bytecode, Rotation::cur())(meta);
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
        copy_type: Type,
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
        copy_type: Type,
        public_tag: public::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let public_entry = LookupEntry::Public {
                tag: (public_tag as u8).expr(),
                tx_idx_or_number_diff: meta.query_advice(self.src_id, Rotation::cur()),
                values: [
                    meta.query_advice(self.src_pointer, Rotation::cur())
                        + meta.query_advice(self.cnt, Rotation::cur()),
                    0.expr(),
                    meta.query_advice(self.byte, Rotation::cur()),
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
        copy_type: Type,
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
        copy_type: Type,
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
        //let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "copy circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;
                // sub circuit need to enable selector
                if self.witness.copy.len() > 0 {
                    for offset in 0..self.witness.copy.len() - 1 {
                        config.q_enable.enable(&mut region, offset)?;
                    }
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (0, 1)
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().1 + witness.copy.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::copy_circuit::CopyCircuit;
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone, Default, Debug)]
    pub struct CopyTestCircuit<F: Field>(CopyCircuit<F, MAX_NUM_ROW>);

    impl<F: Field> Circuit<F> for CopyTestCircuit<F> {
        type Config = CopyCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let (instance_addr, instance_bytecode) =
                BytecodeTable::construct_addr_bytecode_instance_column(meta);
            let q_enable_state = meta.complex_selector();
            let state_table = StateTable::construct(meta, q_enable_state);
            let public_table = PublicTable::construct(meta);
            Self::Config::new(
                meta,
                CopyCircuitConfigArgs {
                    bytecode_table,
                    state_table,
                    public_table,
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

    impl<F: Field> CopyTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self(CopyCircuit::new_from_witness(&witness))
        }
    }

    fn test_simple_copy_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CopyTestCircuit::<Fp>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
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
