use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{BytecodeTable, CopyTable, LookupEntry, PublicTable, StateTable};

use crate::util::{assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes, Challenges};
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

/// Overview:
///    Copy operation in the EVM is usually a data copy of an uncertain length, copying the data from Src to Dst
///    The following operations require the use of Copy operations：
///        CODECOPY： copy data from Bytecode to Memory
///        EXTCODECOPY：copy data from Bytecode to Memory
///        CALLDATACOPY：copy data from Calldata(stored in the State table) to Memory
///        RETURN：copy data from Memory to Returndata
///        RETURNDATACOPY：copy data from Returndata to Memory
///        LOG：copy data from Memory to Log
///        CALLDATA_FROMPUBLIC：copy data from Public Calldata to State Calldata
///        CALLDATA_FROMCALL：copy data from Memory to State Calldata
///    
/// Table layout
/// +----+----------+-------+-------------+------------+----------+---------+------------+-------------+-------+-------+-------+
/// |byte| src_type | sr_id | src_pointer |  src_stamp | dst_type | dst_id | dst_pointer |  dst_stamp  |  cnt  |  len  |  acc  |
/// +---+----------+--------+-------------+------------+----------+--------+-------------+-------------+-------+-------+-------+
///     A row can be divided into two parts, data Src and data Dst，because the length of the copied data is not fixed, the
///   column `len` is defined. In a copy operation, one Byte will generate a row. Len is fixed (the length of this copy),
///   and cnt is increased row by row of.
///     For the meaning of the columns, please refer to the comments of the CopyCircuitConfig structure code below.
///     The values of src_type and dst_type are as follows:
///        Zero, Memory, Calldata, Returndata, PublicLog, PublicCalldata, Bytecode, Null
/// note:
///   acc is the accumulated value of bytes,the value in the acc column is currently only used in two operations: MLOAD and MSTORE.
///   Zero is the default type. If the row is of type Zero, the values are all 0（if Copy needs to be padded with 0s, you can use the Zero type）.
///   if src_type is Null, the sr_id, src_pointer, src_stamp are all 0.
///   if dst_type is Null, the dst_id, dst_pointer, dst_stamp are all 0.
///   
/// How to ensure the correctness of Copy data？
///  Use `Lookup` operation, Lookup data src table, Lookup data target table.
///  rules for Lookup data source:
///     1. src_type is Zero/Null: no Lookup is performed.
///     2. src_type is Memory/Calldata/Runterdata:  
///          Lookup src(Copy Circuit table): <tag=Memory/Calldata/Returndata, src_id, src_pointer+cnt, src_stamp+cnt, byte, `is_write=0`>
///          Lookup target(State Circuit table): <tag, call_id, pointer_lo, stamp, value_lo, is_write>
///         That is `LookupEntry::State`
///     3. src_type is Bytecode:
///          Lookup src(Copy Circuit table): <src_pointer+cnt, src_id, byte>
///          Lookup target(Bytecode Circuit table): <pc, addr, bytecode>
///          That is `LookupEntry::State`
///     4. src_type is PublicCalldata:
///         Lookup src(Copy Circuit table): <tag=Calldata, src_id, src_pointer+cnt, byte>
///         Look target(Public Circuit table): <tag, tx_idx, idx, value>
///
///   rules for Lookup data target:
///     1. dst_type is Zero/Null: no Lookup is performed.
///     2. dst_type is Memory/Calldata/Runterdata：
///          Lookup src(Copy Circuit table): <tag=Memory/Calldata/Returndata, src_id, src_pointer+cnt, src_stamp+cnt, byte, `is_write=1`>
///          Lookup target(State Circuit table): <tag, call_id, pointer_lo, stamp, value_lo, is_write>
///         That is `LookupEntry::State`
///     3. dst_type is PublicLog:
///          Lookup src(Copy Circuit table): <tag=tx_log, log_tag=bytes, dst id, src_pointer + cnt, dst_stamp, byte, len>
///          Lookup target(Public Circuit table): <tag, block_tx_idx, idx, value>
///          That is `LookupEntry::Public`
///          note: the tag mentioned here is the Tag of Public
///
///  For example：
///    Execution CODECOPY instruction, src_type: Bytecode, dst_type: Memory
///     Lookup data source(Bytecode table):
///         Lookup src(Copy Circuit table): <src_pointer+cnt, src_id, byte>
///         Lookup target(Bytecode Circuit table): <pc, addr, bytecode>
///     Lookup data target(State table):
///         Lookup src(Copy Circuit table): <tag=Memory, src_id, src_pointer+cnt, src_stamp+cnt, byte, is_write=1>
///         Lookup target(State Circuit): <tag, call_id, pointer_lo, stamp, value_lo, is_write>
///
/// Table example:
///    CODECOPY operation, src_type is Bytecode, dst_type is Memory(stored in the State table)
///     | byte | src_type   | src_id | src_pointer | src_stamp | dst_type | dst_id | dst_pointer | dst_stamp  | cnt | len |     acc      |
///     |------|------------|-------|--------------|-----------|----------|--------|------------|-------------|-----|-----|--------------|
///     | 0x12 | `Bytecode` | 0xaa  |     0x00    |    nil     | `Memory` | callid |   0x00    |    stamp     | 0   | 5   | 0x12         |
///     | 0x34 | `Bytecode` | 0xaa  |     0x00    |    nil    | `Memory` | callid |    0x00    |    stamp     | 1   | 5   | 0x1234       |
///     | 0x56 | `Bytecode` | 0xaa  |     0x00    |    nil    | `Memory` | callid |    0x00    |    stamp     | 2   | 5   | 0x123456     |
///     | 0x78 | `Bytecode` | 0xaa  |     0x00    |    nil    | `Memory` | callid |    0x00    |    stamp     | 3   | 5   | 0x12345678   |
///     | 0x9a | `Bytecode` | 0xaa  |     0x00    |    nil    | `Memory` | callid |    0x00    |    stamp     | 4   | 5   | 0x123456789a |

#[derive(Clone)]
pub struct CopyCircuitConfig<F: Field> {
    pub q_first_rows: Selector,
    pub q_enable: Selector,
    /// The byte value that is copied
    pub byte: Column<Advice>,
    /// The source id, block_tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: Column<Advice>,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: Column<Advice>,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: Column<Advice>,
    /// The destination id, block_tx_idx for PublicLog, call_id for Memory, Calldata, Returndata
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
    pub copy_table: CopyTable,
    /// challenges
    pub challenges: Challenges,
}

impl<F: Field> SubCircuitConfig<F> for CopyCircuitConfig<F> {
    type ConfigArgs = CopyCircuitConfigArgs<F>;
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            bytecode_table,
            state_table,
            public_table,
            copy_table,
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let CopyTable {
            src_tag,
            src_id,
            src_pointer,
            src_stamp,
            dst_tag,
            dst_id,
            dst_pointer,
            dst_stamp,
            cnt,
            len,
            acc,
        } = copy_table;
        // initialize columns
        let q_enable = meta.complex_selector();
        let byte = meta.advice_column();
        let len_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            len,
            None,
        );
        let cnt_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            cnt,
            None,
        );

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
        // construct config object
        let q_first_rows = meta.selector();
        let config = Self {
            q_first_rows,
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

        // Copy gate constraints
        // 1) if len=0, it means that the current row should be a pad row, that is, the current row is not the actual
        // data and is specially used to make up the number of table rows, that is, all value are 0.
        // 2) if src_type=Zero, byte, src_id, src_pointer, src_stamp are all 0.
        //    if dst_type=Zero, byte, dst_id, dst_pointer, dst_stamp are all 0.
        // 3) if src_type=Null,src_id, src_pointer, src_stamp are all 0.
        //    if dst_type=Null, dst_id, dst_pointer, dst_stamp are all 0.
        // 4) if len-cnt-1=0, that is, the current row is the last byte copied by this copy operation, then the next row
        // should be the first row of another copy operation or the padding row, so cnt_next should be 0.
        //    if len=0, the same as len-cnt-1=0, that is, the current line is a padding line, then cnt_next should be 0
        // 5) if len-cnt-1 != 0 && cnt!=0, it means that the current row is the actual data of Copy, and cnt is increasing,
        // so cnt_next-cnt_cur-1=0，and src_type_next=src_type_cur, src_id_next=src_id_cur, src_pointer_next=src_pointer_cur,
        // dst_type_next=dst_type_cur,dst_id_next=dst_id_cur, dst_pointer_next=dst_pointer_cur,dst_stamp_next=dst_stamp_cur, len_next=len_cur
        // 6) if cnt=0, acc=byte
        // 7) if cnt!=0, it means that the current data is actually copied data, and the value of acc should satisfy the operation `acc=byte+acc_prev*256`
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

        meta.create_gate("COPY_q_first_rows constrains", |meta| {
            let q_first_rows = meta.query_selector(config.q_first_rows);
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

            let len_is_zero = config.len_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let len_sub_cnt_one_is_zero = config.len_sub_cnt_one_is_zero.expr();

            let mut constraints = vec![
                ("q_first_rows=1 ==> cnt=0", q_first_rows.clone() * cnt),
                ("q_first_rows=1 ==> byte=0", q_first_rows.clone() * byte),
                ("q_first_rows=1 ==> src_id=0", q_first_rows.clone() * src_id),
                (
                    "q_first_rows=1 ==> src_tag is 0",
                    q_first_rows.clone() * src_tag,
                ),
                (
                    "q_first_rows=1 ==> src_pointer=0",
                    q_first_rows.clone() * src_pointer,
                ),
                (
                    "q_first_rows=1 ==> src_stamp=0",
                    q_first_rows.clone() * src_stamp,
                ),
                ("q_first_rows=1 ==> dst_id=0", q_first_rows.clone() * dst_id),
                (
                    "q_first_rows=1 ==> dst_tag is 0",
                    q_first_rows.clone() * dst_tag,
                ),
                (
                    "q_first_rows=1 ==> dst_pointer=0",
                    q_first_rows.clone() * dst_pointer,
                ),
                (
                    "q_first_rows=1 ==> dst_stamp=0",
                    q_first_rows.clone() * dst_stamp,
                ),
                ("q_first_rows=1 ==> len=0", q_first_rows.clone() * len),
                ("q_first_rows=1 ==> acc=0", q_first_rows.clone() * acc),
                (
                    "q_first_rows=1 ==> len_is_zero=1",
                    q_first_rows.clone() * (1.expr() - len_is_zero),
                ),
                (
                    "q_first_rows=1 ==> cnt_is_zero=1",
                    q_first_rows.clone() * (1.expr() - cnt_is_zero),
                ),
                (
                    "q_first_rows=1 ==> len_sub_cnt_one_is_zero=0",
                    q_first_rows.clone() * len_sub_cnt_one_is_zero,
                ),
            ];

            constraints
        });

        // use Lookup operation to ensure the correctness of Copy data
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
        config.dst_public_log_data_lookup(
            meta,
            "COPY_dst_log_lookup",
            Tag::PublicLog,
            public::Tag::TxLogData,
        );
        config
    }
}

impl<F: Field> CopyCircuitConfig<F> {
    /// assign data to circuit table cell
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

        assign_advice_or_fixed_with_u256(region, offset, &row.byte, self.byte)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.src_id, self.src_id)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.src_pointer, self.src_pointer)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.src_stamp, self.src_stamp)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.dst_id, self.dst_id)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.dst_pointer, self.dst_pointer)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.dst_stamp, self.dst_stamp)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.cnt, self.cnt)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.len, self.len)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.acc, self.acc)?;

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

    /// set the annotation information of the circuit column
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

    /// Lookup data source:
    ///     lookup src: Copy circuit
    ///     lookup target: Bytecode circut table
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

    /// Lookup data source:
    ///     lookup src: Copy circuit
    ///     lookup target: State circut table
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

    /// Lookup data source:
    ///     lookup src: Copy circuit
    ///     lookup target: Public circut table
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
                block_tx_idx: meta.query_advice(self.src_id, Rotation::cur()),
                values: [
                    0.expr(),
                    0.expr(),
                    meta.query_advice(self.src_pointer, Rotation::cur())
                        + meta.query_advice(self.cnt, Rotation::cur()),
                    meta.query_advice(self.byte, Rotation::cur()),
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

    /// Lookup data target:
    ///     lookup src: Copy circuit
    ///     lookup target: Public circut table
    pub fn dst_public_log_data_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &str,
        copy_type: Tag,
        public_tag: public::Tag,
    ) {
        meta.lookup_any(name, |meta| {
            let public_entry = LookupEntry::Public {
                tag: (public_tag as u8).expr(),
                block_tx_idx: meta.query_advice(self.dst_id, Rotation::cur()),
                values: [
                    meta.query_advice(self.dst_stamp, Rotation::cur()), // log index
                    0.expr(),
                    meta.query_advice(self.src_pointer, Rotation::cur()) // idx
                        + meta.query_advice(self.cnt, Rotation::cur()),
                    meta.query_advice(self.byte, Rotation::cur()), // byte
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

    /// Lookup data target:
    ///     lookup src: Copy circuit
    ///     lookup target: State circut table
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
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "copy circuit",
            |mut region| {
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assgin circuit table value
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;

                for offset in 0..Self::unusable_rows().0 {
                    config.q_first_rows.enable(&mut region, offset)?;
                }

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
    use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
    use crate::keccak_circuit::{KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs};
    use crate::public_circuit::{PublicCircuit, PublicCircuitConfig, PublicCircuitConfigArgs};
    use crate::state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs};
    use crate::table::{FixedTable, KeccakTable};
    use crate::util::{chunk_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::{bytecode, U256};
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;
    use std::str::FromStr;

    #[derive(Clone)]
    pub struct CopyTestCircuitConfig<F: Field> {
        pub bytecode_circuit: BytecodeCircuitConfig<F>,
        pub keccak_circuit: KeccakCircuitConfig<F>,
        pub public_circuit: PublicCircuitConfig<F>,
        pub copy_circuit: CopyCircuitConfig<F>,
        pub state_circuit: StateCircuitConfig<F>,
        pub fixed_circuit: FixedCircuitConfig<F>,
        pub challenges: Challenges,
    }

    impl<F: Field> SubCircuitConfig<F> for CopyTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            // initialize columns
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let q_enable_state = meta.complex_selector();
            let state_table = StateTable::construct(meta, q_enable_state);

            #[cfg(not(feature = "no_public_hash"))]
            let instance_hash = PublicTable::construct_hash_instance_column(meta);
            #[cfg(not(feature = "no_public_hash"))]
            let q_enable_public = meta.complex_selector();
            let public_table = PublicTable::construct(meta);

            let fixed_table = FixedTable::construct(meta);

            let keccak_table = KeccakTable::construct(meta);

            let q_enable_copy = meta.complex_selector();
            let copy_table = CopyTable::construct(meta, q_enable_copy);

            let challenges = Challenges::construct(meta);
            let bytecode_circuit = BytecodeCircuitConfig::new(
                meta,
                BytecodeCircuitConfigArgs {
                    q_enable: q_enable_bytecode,
                    bytecode_table,
                    fixed_table,
                    keccak_table,
                    public_table,
                    challenges,
                },
            );
            let state_circuit = StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    q_enable: q_enable_state,
                    state_table,
                    fixed_table,
                    challenges,
                },
            );

            #[cfg(not(feature = "no_public_hash"))]
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

            #[cfg(feature = "no_public_hash")]
            let public_circuit =
                PublicCircuitConfig::new(meta, PublicCircuitConfigArgs { public_table });

            // construct config object
            let copy_circuit = CopyCircuitConfig::new(
                meta,
                CopyCircuitConfigArgs {
                    bytecode_table,
                    state_table,
                    public_table,
                    copy_table,
                    challenges,
                },
            );
            let keccak_circuit = KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table,
                    challenges,
                },
            );
            let fixed_circuit =
                FixedCircuitConfig::new(meta, FixedCircuitConfigArgs { fixed_table });
            CopyTestCircuitConfig {
                bytecode_circuit,
                keccak_circuit,
                public_circuit,
                copy_circuit,
                state_circuit,
                fixed_circuit,
                challenges,
            }
        }
    }

    /// CopyTestCircuit is a Circuit used for testing
    #[derive(Clone, Default, Debug)]
    pub struct CopyTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub copy_circuit: CopyCircuit<F, MAX_NUM_ROW>,
        pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW, MAX_CODESIZE>,
        pub keccak_circuit: KeccakCircuit<F, MAX_NUM_ROW>,
        pub state_circuit: StateCircuit<F, MAX_NUM_ROW>,
        pub public_circuit: PublicCircuit<F, MAX_NUM_ROW>,
        pub fixed_circuit: FixedCircuit<F>,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for CopyTestCircuit<F, MAX_NUM_ROW> {
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
            let challenges = config.challenges.values(&mut layouter);
            self.bytecode_circuit.synthesize_sub(
                &config.bytecode_circuit,
                &mut layouter,
                &challenges,
            )?;
            self.public_circuit.synthesize_sub(
                &config.public_circuit,
                &mut layouter,
                &challenges,
            )?;
            self.copy_circuit
                .synthesize_sub(&config.copy_circuit, &mut layouter, &challenges)?;
            self.state_circuit
                .synthesize_sub(&config.state_circuit, &mut layouter, &challenges)?;
            // when feature `no_fixed_lookup` is on, we don't do synthesize
            #[cfg(not(feature = "no_fixed_lookup"))]
            self.fixed_circuit
                .synthesize_sub(&config.fixed_circuit, &mut layouter, &challenges)?;

            self.keccak_circuit.synthesize_sub(
                &config.keccak_circuit,
                &mut layouter,
                &challenges,
            )?;
            Ok(())
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> CopyTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness) -> Self {
            Self {
                bytecode_circuit: BytecodeCircuit::new_from_witness(&witness),
                public_circuit: PublicCircuit::new_from_witness(&witness),
                copy_circuit: CopyCircuit::new_from_witness(&witness),
                state_circuit: StateCircuit::new_from_witness(&witness),
                fixed_circuit: FixedCircuit::new_from_witness(&witness),
                keccak_circuit: KeccakCircuit::new_from_witness(&witness),
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bytecode_circuit.instance());
            vec.extend(self.public_circuit.instance());
            vec.extend(self.copy_circuit.instance());
            vec.extend(self.state_circuit.instance());
            vec.extend(self.fixed_circuit.instance());
            vec.extend(self.keccak_circuit.instance());
            vec
        }
    }

    fn test_simple_copy_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = CopyTestCircuit::<Fp, MAX_NUM_ROW>::new(witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    /// test the functionality of CopyCircuit using CODECOPY and EXTCODECOPY
    #[test]
    fn test_copy_parser() {
        let a = U256::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let code = bytecode! {
            PUSH1(0x1E)
            PUSH1(0x03)
            PUSH1(0x00)
            CODECOPY
            PUSH1(0x1E)
            PUSH1(0x03)
            PUSH1(0x00)
            PUSH32(a)
            EXTCODECOPY
            PUSH1(0x1E)
            PUSH1(0xef)
            PUSH1(0x1F)
            CODECOPY
            PUSH1(0x1E)
            PUSH1(0xef)
            PUSH1(0x1F)
            PUSH32(a)
            EXTCODECOPY
            STOP
        };
        let machine_code = code.to_vec();
        let trace = trace_parser::trace_program(&machine_code, &[]);
        // create witness object
        let witness: Witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));
        //witness.print_csv();

        // execution circuit
        let prover = test_simple_copy_circuit(witness);
        prover.assert_satisfied_par();
    }
}
