// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{BYTECODE_NUM_PADDING, POSEIDON_HASH_BYTES_IN_FIELD};
use crate::table::{BytecodeTable, FixedTable, PublicTable};
use crate::table::{LookupEntry, PoseidonTable};
use crate::util::{
    assign_advice_or_fixed_with_u256, convert_u256_to_64_bytes, Challenges, SubCircuit,
    SubCircuitConfig,
};
use crate::witness::bytecode::Row;
use crate::witness::{public, Witness};
use eth_types::{Field, U256};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::{and, not, or, pow_of_two, select, Expr};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use poseidon_circuit::HASHABLE_DOMAIN_SPEC;
use std::marker::PhantomData;

/// Overview:
///  bytecode circuit is used to constrain the Bytecode of the contract and provide the source basis of bytecode for other circuits.
///  other sub-circuits can use Lookup constraints to verify whether the operated bytecode is legal.
///  the Bytecode table may store more than just the Bytecode of one contract.
///  the Bytecodes of different contracts are identified by address, and Bytecode and address have a unique one-to-one correspondence.
///  for Bytecode of the same contract, pc is the unique identifier of opcode or no_code (byte of push).
/// When processing Bytecode, Bytecode is divided into two categories:
///    1. Opcode (non-PUSH): operation instructions, such as ADD, SUB, CODECOPY
///    2. Opcode (PUSH): PUSH1~PUSH32, and Byte of PUSH
///
/// Table layout:
/// +------+----+----------+----------+----------+--------+--------+-----+---------+--------------+-----------+---------------+--------------+
/// | addr | pc | bytecode | value_hi | value_lo | acc_hi | acc_lo | cnt | is_high | cnt_is_zero  | cnt_is_15 | addr_unchange | addr_is_zero |
/// +------+----+----------+----------+----------+--------+-------+-----+---------+--------------+------------+---------------+--------------+
///  For the meaning of the columns, please refer to the comments of the BytecodeCircuitConfig structure code below.
/// cnt: if it is a non-PUSH Opcode, cnt=0. For the PUSH instruction, cnt is the number of bytes of PUSH.
///      for example, PUSH1 --> cnt=1, PUSH2 --> cnt=2, PUSH31 --> cnt=31, PUSH32 --> cnt=32.
///      for no_code, the value of cnt is (0~cnt-1)
/// is_high: if cnt >=16, then is_high is 1, if cnt < 16 then is_high 0
///          is_high mainly used to assist in calculating the value of acc (the value of acc is stipulated to be up to 16 bytes)
/// acc_hi: cnt >=16 Bytecode  performs this calculation, acc_hi_pre * 256 + bytecode, that is, calculates the accumulated value of byte
///  acc_lo: cnt < 16 Bytecode performs this calculation, acc_lo_pre * 256 + bytecode, that is, calculates the cumulative value of byte
///  value_hi: The final accumulated value of Bytecode with cnt >= 16, that is, the final acc_hi
///  value_lo: The final accumulated value of Bytecode with cnt < 15, that is, the final acc_lo
///
/// How to ensure the correctness of Opcode？
///    Use `Lookup` operation
///    Fixed circuit table stores all Opcodes. In theory, all Opcodes in Bytecode should come from Fixed circuit.
///    that is, lookup src: Bytecode Circuit, lookup target: Fixed Circuit table， use LookupEntry::Fixed
///
/// How to ensure the correctness of Push byte？
///  Use `Lookup` operation
///  the data of PUSH instruction PUSH is bytes, so the range of a byte is 0~255
///  Fixed circuit table stores all values from 0 to 255.
///  that is, lookup src: Bytecode Circuit, lookup target: Fixed Circuit table， use LookupEntry::U8

#[allow(unused)]
#[derive(Clone)]
pub struct BytecodeHashAuxConfig<F> {
    /// poseidon hash - bytecode hash
    hash: Column<Advice>,
    /// poseidon hash - control lookup
    control_length: Column<Advice>,
    /// poseidon hash - field input
    field_input: Column<Advice>,
    /// poseidon hash -- bytes in field index
    /// The range of values is 1 to 31.
    bytes_in_field_index: Column<Advice>,
    /// bytes_in_field_index can be used alone, so IsZeroConfig is not applicable here
    bytes_in_field_inv: Column<Advice>,
    /// poseidon hash -- determine the boundary position
    is_field_border: Column<Advice>,
    padding_shift: Column<Advice>,
    /// field_index -- the range of value is 1 or 2.
    /// Distinguish between input_0 or input_1, for example, index 0 to 30 results in 1, and 31 to 61 results in 2.
    field_index: Column<Advice>,
    /// field_index can be used alone, so IsZeroConfig is not applicable here
    field_index_inv: Column<Advice>,
    _marker: PhantomData<F>,
}

#[allow(unused)]
#[derive(Clone)]
pub struct BytecodeCircuitConfig<F> {
    q_first_rows: Selector,
    q_enable: Selector,
    /// the contract address of the bytecodes (need to copy from public input)
    addr: Column<Advice>,
    /// the index that program counter points to
    pc: Column<Advice>,
    /// bytecode, operation code or pushed value (need to copy from public input)
    bytecode: Column<Advice>,
    /// pushed value, high 128 bits
    value_hi: Column<Advice>,
    /// pushed value, low 128 bits
    value_lo: Column<Advice>,
    /// accumulated value, high 128 bits. accumulation will go X times for PUSHX
    acc_hi: Column<Advice>,
    /// accumulated value, low 128 bits. accumulation will go X times for PUSHX
    acc_lo: Column<Advice>,
    /// count for accumulation, accumulation will go X times for PUSHX
    cnt: Column<Advice>,
    /// whether count is equal or larger than 16
    is_high: Column<Advice>,
    /// the actual length of the contract bytecode (excluding padding bytecode)
    length: Column<Advice>,
    /// whether the current bytecode is the bytecode of padding
    is_padding: Column<Advice>,
    /// for chip to determine whether cnt is 0
    cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// for chip to determine whether cnt is 15
    cnt_is_15: IsZeroConfig<F>,
    /// for chip to check if addr is changed from previous row
    addr_unchange: IsZeroConfig<F>,
    /// for chip to check if addr is changed from next row
    addr_unchange_next: IsZeroConfig<F>,
    /// for chip to check if addr is zero, which means the row is padding
    addr_is_zero: IsZeroWithRotationConfig<F>,
    poseidon_aux_conf: BytecodeHashAuxConfig<F>,
    // table used for lookup
    fixed_table: FixedTable,
    public_table: PublicTable,
    poseidon_table: PoseidonTable,
}

pub struct BytecodeCircuitConfigArgs<F> {
    pub q_enable: Selector,
    pub bytecode_table: BytecodeTable<F>,
    pub fixed_table: FixedTable,
    pub public_table: PublicTable,
    pub poseidon_table: PoseidonTable,
    /// Challenges
    pub challenges: Challenges,
}

impl<F: Field> SubCircuitConfig<F> for BytecodeCircuitConfig<F> {
    type ConfigArgs = BytecodeCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            bytecode_table,
            fixed_table,
            public_table,
            poseidon_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let BytecodeTable {
            addr,
            pc,
            bytecode,
            value_hi,
            value_lo,
            cnt,
            cnt_is_zero,
        } = bytecode_table;

        let challenges_expr = challenges.exprs(meta);

        // initialize columns
        let acc_hi = meta.advice_column();
        let acc_lo = meta.advice_column();
        let is_high = meta.advice_column();
        let length = meta.advice_column();
        let is_padding = meta.advice_column();
        let _cnt_minus_15_inv = meta.advice_column();
        let cnt_is_15 = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let cnt = meta.query_advice(cnt, Rotation::cur());
                cnt - 15.expr()
            },
            _cnt_minus_15_inv,
        );
        let _addr_diff_inv = meta.advice_column();
        let addr_unchange = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let addr_cur = meta.query_advice(addr, Rotation::cur());
                let addr_prev = meta.query_advice(addr, Rotation::prev());
                addr_cur - addr_prev
            },
            _addr_diff_inv,
        );

        let _addr_next_diff_inv = meta.advice_column();
        let addr_unchange_next = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let addr_next = meta.query_advice(addr, Rotation::next());
                let addr_cur = meta.query_advice(addr, Rotation::cur());
                addr_next - addr_cur
            },
            _addr_next_diff_inv,
        );
        let addr_is_zero = IsZeroWithRotationChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            addr,
            None,
        );

        let poseidon_aux_conf = BytecodeHashAuxConfig::new(meta);

        // construct config object
        let q_first_rows = meta.selector();
        let config = Self {
            q_first_rows,
            q_enable,
            addr,
            pc,
            bytecode,
            value_hi,
            value_lo,
            acc_hi,
            acc_lo,
            cnt,
            is_high,
            length,
            is_padding,
            cnt_is_zero,
            cnt_is_15,
            addr_unchange,
            addr_unchange_next,
            addr_is_zero,
            fixed_table,
            public_table,
            poseidon_aux_conf,
            poseidon_table,
        };

        // constrain pc
        // 1. if addr changes, it means it is a new contract, and pc should start from 0
        // 2. addr has not changed, indicating that it is the same contract, and pc should be increasing
        meta.create_gate("BYTECODE_pc_increase_or_zero", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let addr_unchange = config.addr_unchange.expr();
            let pc_cur = meta.query_advice(config.pc, Rotation::cur());
            let pc_prev = meta.query_advice(config.pc, Rotation::prev());
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            vec![
                (
                    "addr_change(new contract bytecode) --> pc=0",
                    q_enable.clone() * (1.expr() - addr_unchange.clone()) * pc_cur.clone(),
                ),
                (
                    "addr_unchange && addr_is_not_zero --> pc_cur -= pc_prev+1",
                    q_enable * addr_unchange
                        * (1.expr() - addr_is_zero) // this row is not padding
                        * (pc_cur - pc_prev - 1.expr()),
                ),
            ]
        });

        // constrain padding row, the padding row values are all 0
        // note: the data in the padding row has no actual meaning, it is just to make up the number of rows in the table
        meta.create_gate("BYTECODE_addr_is_zero", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            let pc = meta.query_advice(config.pc, Rotation::cur());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let acc_hi = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo = meta.query_advice(config.acc_lo, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let is_high = meta.query_advice(config.is_high, Rotation::cur());
            let hash = meta.query_advice(config.poseidon_aux_conf.hash, Rotation::cur());

            let field_input =
                meta.query_advice(config.poseidon_aux_conf.field_input, Rotation::cur());
            let bytes_in_field_index = meta.query_advice(
                config.poseidon_aux_conf.bytes_in_field_index,
                Rotation::cur(),
            );
            let field_index =
                meta.query_advice(config.poseidon_aux_conf.field_index, Rotation::cur());
            let is_field_border =
                meta.query_advice(config.poseidon_aux_conf.is_field_border, Rotation::cur());
            let padding_shift =
                meta.query_advice(config.poseidon_aux_conf.padding_shift, Rotation::cur());

            vec![
                ("pc is zero", q_enable.clone() * addr_is_zero.clone() * pc),
                (
                    "bytecode is zero",
                    q_enable.clone() * addr_is_zero.clone() * bytecode,
                ),
                (
                    "value_hi is zero",
                    q_enable.clone() * addr_is_zero.clone() * value_hi,
                ),
                (
                    "value_lo is zero",
                    q_enable.clone() * addr_is_zero.clone() * value_lo,
                ),
                (
                    "acc_hi is zero",
                    q_enable.clone() * addr_is_zero.clone() * acc_hi,
                ),
                (
                    "acc_lo is zero",
                    q_enable.clone() * addr_is_zero.clone() * acc_lo,
                ),
                ("cnt is zero", q_enable.clone() * addr_is_zero.clone() * cnt),
                (
                    "is_high is zero",
                    q_enable.clone() * addr_is_zero.clone() * is_high,
                ),
                (
                    "hash is zero",
                    q_enable.clone() * addr_is_zero.clone() * hash,
                ),
                (
                    "field_input is zero",
                    q_enable.clone() * addr_is_zero.clone() * field_input,
                ),
                (
                    "bytes_in_field_index is zero",
                    q_enable.clone() * addr_is_zero.clone() * bytes_in_field_index,
                ),
                (
                    "field_index is one",
                    q_enable.clone() * addr_is_zero.clone() * (1.expr() - field_index),
                ),
                (
                    "is_field_border is zero",
                    q_enable.clone() * addr_is_zero.clone() * is_field_border,
                ),
                (
                    "padding_shift is 256^(BYTES_IN_FIELD)",
                    q_enable.clone()
                        * addr_is_zero.clone()
                        * (padding_shift
                            - 1.expr() * pow_of_two::<F>(8 * POSEIDON_HASH_BYTES_IN_FIELD)),
                ),
            ]
        });

        // cnt_prev is not 0, indicating that the current row is the byte pushed by the PUSH instruction
        // the row where the byte of the PUSH instruction is located has the following characteristics:
        // 1. the value of `cnt` is decreasing, so cnt_prev - cnt_cur = 1
        // 2. If the current row is row 15, then is_high_prev-is_high_cur=0, because when cnt >=16, is_high is 1, and when cnt <16, is_high is 0
        // 3. for rows with cnt < 16, the value of acc_hi is unchanged， so acc_hi_cur-acc_hi_prev=0
        //    for rows with cnt >= 16, the value of acc_hi is acc_hi_prev*256 + bytecode
        // 4. for rows with cnt >= 16, the value of acc_lo is 0, and acc_lo_prev=acc_lo_cur
        //    for rows with cnt < 16, the value of acc_lo is acc_lo_prev*256 + bytecode
        // 5. the value_hi of all rows are equal, and the value_lo is also equal, that is, value_lo_cur=value_lo_prev, value_hi_lo_cur=value_hi_prev
        // cnt_prev!=0 && cnt=0, the last byte of push
        meta.create_gate("BYTECODE_PUSH_BYTE", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let value_hi_cur = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo_cur = meta.query_advice(config.value_lo, Rotation::cur());
            let value_hi_prev = meta.query_advice(config.value_hi, Rotation::prev());
            let value_lo_prev = meta.query_advice(config.value_lo, Rotation::prev());
            let acc_hi_cur = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo_cur = meta.query_advice(config.acc_lo, Rotation::cur());
            let acc_hi_prev = meta.query_advice(config.acc_hi, Rotation::prev());
            let acc_lo_prev = meta.query_advice(config.acc_lo, Rotation::prev());
            let cnt_cur = meta.query_advice(config.cnt, Rotation::cur());
            let cnt_prev = meta.query_advice(config.cnt, Rotation::prev());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            let cnt_is_15 = config.cnt_is_15.expr();
            let is_high_prev = meta.query_advice(config.is_high, Rotation::prev());
            let is_high_cur = meta.query_advice(config.is_high, Rotation::cur());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            let is_push_byte = 1.expr() - cnt_is_zero_prev;
            let is_push_last_byte = is_push_byte.clone() * cnt_is_zero;
            vec![
                // cnt is decreasing
                (
                    "cnt_prev = cnt_cur+1",
                    q_enable.clone() * is_push_byte.clone() * (cnt_prev - cnt_cur - 1.expr()),
                ),
                // when cnt >=16, is_high is 1, and when cnt <16, is_high is 0
                (
                    "cnt >=16 --> is_high = 1",
                    q_enable.clone()
                        * is_push_byte.clone()
                        * (is_high_prev - is_high_cur.clone() - cnt_is_15)
                ),
                (
                    "value_hi_cur = value_hi_prev",
                    q_enable.clone() * is_push_byte.clone() * (value_hi_cur.clone() - value_hi_prev)
                ),
                (
                    "value_lo_cur = value_lo_prev",
                    q_enable.clone() * is_push_byte.clone() * (value_lo_cur.clone() - value_lo_prev),
                ),
                // cnt >= 16 ==> acc_hi = acc_hi_prev*256 + bytecode
                // cnt < 16 ==> acc_hi = acc_hi_prev
                (
                    "cnt >= 16 --> acc_hi = acc_hi_prev*256 + bytecode, cnt < 16 --> acc_hi = acc_hi_prev",
                    q_enable.clone()
                        * is_push_byte.clone()
                        * (acc_hi_prev.clone()
                        + is_high_cur.clone() * (255.expr() * acc_hi_prev + bytecode.clone())
                        - acc_hi_cur.clone()),
                ),
                // cnt >= 16 ==> acc_lo=0, acc_lo = acc_lo_prev
                // cnt < 16 ==> acc_lo=acc_lo_prev*256 + bytecode
                (
                    "cnt >= 16 --> acc_lo=0",
                    q_enable.clone() * is_push_byte.clone() * is_high_cur.clone() * acc_lo_cur.clone(),
                ),
                (
                    "cnt >= 16 --> acc_lo = acc_lo_prev,  cnt < 16 --> acc_lo=acc_lo_prev*256 + bytecode",
                    q_enable.clone()
                        * is_push_byte.clone()
                        * (acc_lo_prev.clone()
                        + (1.expr() - is_high_cur.clone()) * (255.expr() * acc_lo_prev + bytecode)
                        - acc_lo_cur.clone()),
                ),
                // the last byte of push, value_hi=acc_hi, value_lo=acc_lo
                (
                    "is_push_last_byte --> value_hi = acc_hi",
                    q_enable.clone() * is_push_last_byte.clone() * (value_hi_cur - acc_hi_cur),
                ),
                (
                    "is_push_last_byte --> value_lo = acc_lo",
                    q_enable * is_push_last_byte.clone() * (value_lo_cur - acc_lo_cur),
                )
            ]
        });

        // if it is Bytecode or Opcode, and it is not a PUSH instruction, then cnt, cnt_prev, acc_hi,
        //  acc_lo, value_hi, value_lo、is_high are all 0.
        meta.create_gate("BYTECODE_OPCODE(NOT_PUSH)", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let acc_hi = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo = meta.query_advice(config.acc_lo, Rotation::cur());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let is_high = meta.query_advice(config.is_high, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());

            // if one of the conditions is not met, it is 0;
            // if all conditions are met, it is 1
            let opcode_is_no_push = cnt_is_zero_prev * cnt_is_zero * (1.expr() - addr_is_zero);

            vec![
                (
                    "value_hi is zero",
                    q_enable.clone() * opcode_is_no_push.clone() * value_hi,
                ),
                (
                    "value_lo is zero",
                    q_enable.clone() * opcode_is_no_push.clone() * value_lo,
                ),
                (
                    "acc_hi is zero",
                    q_enable.clone() * opcode_is_no_push.clone() * acc_hi,
                ),
                (
                    "acc_lo is zero",
                    q_enable.clone() * opcode_is_no_push.clone() * acc_lo,
                ),
                (
                    "is_high is zero",
                    q_enable.clone() * opcode_is_no_push.clone() * is_high,
                ),
            ]
        });

        // in the row where Opcode (PUSH instruction) is located, cnt must not be 0, and the values of acc_hi and acc_lo are both 0.
        meta.create_gate("BYTECODE_OPCODE(PUSH)", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let acc_hi_cur = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo_cur = meta.query_advice(config.acc_lo, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());

            // cnt_prev=0 && cnt_cur !=0 ----> OPCODE(PUSH instruction)
            let opcode_is_push = cnt_is_zero_prev * (1.expr() - cnt_is_zero);

            vec![
                // acc_hi and acc_lo are both 0
                (
                    "acc_hi_cur is zero",
                    q_enable.clone() * opcode_is_push.clone() * acc_hi_cur,
                ),
                (
                    "acc_lo_cur is zero",
                    q_enable.clone() * opcode_is_push.clone() * acc_lo_cur,
                ),
            ]
        });

        // constrain hash
        // If the addr of the next line changes from the addr of the current line, it means that the
        // current line is the last bytecode of the current contract code, that is, the current line record has a hash value.
        // If the addr of the next row does not change from the addr of the current row, the hash field value of the current row is 0.
        meta.create_gate("BYTECODE_hash", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let hash_cur = meta.query_advice(config.poseidon_aux_conf.hash, Rotation::cur());
            let hash_next = meta.query_advice(config.poseidon_aux_conf.hash, Rotation::next());

            let addr_unchange_next = config.addr_unchange_next.expr();
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            let addr_is_not_zero = 1.expr() - addr_is_zero;

            vec![(
                "addr_is_not_zero && addr_unchange_next --> hash_cur = hash_next",
                q_enable.clone()
                    * addr_is_not_zero.clone()
                    * addr_unchange_next.clone()
                    * (hash_cur - hash_next),
            )]
        });

        meta.create_gate("BYTECODE_padding_value", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_padding = meta.query_advice(config.is_padding, Rotation::cur());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            vec![(
                "is_padding == 1 --> bytecode is zero",
                q_enable.clone() * is_padding.clone() * bytecode,
            )]
        });

        meta.create_gate("BYTECODE_not_zero_value_padding", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let pc = meta.query_advice(config.pc, Rotation::cur());
            let length_cur = meta.query_advice(config.length, Rotation::cur());
            let length_next = meta.query_advice(config.length, Rotation::next());
            let addr_unchange_next = config.addr_unchange_next.expr();
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            let addr_is_not_zero = 1.expr() - addr_is_zero;
            let is_padding_cur = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());
            let field_index =
                meta.query_advice(config.poseidon_aux_conf.field_index, Rotation::cur());
            let padding_shift =
                meta.query_advice(config.poseidon_aux_conf.padding_shift, Rotation::cur());

            vec![
                (
                    "addr_is_not_zero && addr_unchange_next --> length_cur=length_next",
                    q_enable.clone()
                        * addr_is_not_zero.clone()
                        * addr_unchange_next.clone()
                        * (length_cur.clone() - length_next),
                ),
                (
                    "addr_is_not_zero && is_padding_next && is_not_padding_cur --> length - pc = 1",
                    q_enable.clone()
                        * addr_is_not_zero.clone()
                        * (1.expr() - is_padding_cur.clone())
                        * is_padding_next.clone()
                        * (length_cur.clone() - pc.clone() - 1.expr()),
                ),
                (
                    "addr_change_next ---> pc(PC starts counting from 0) - length_cur - 32 = 0",
                    q_enable.clone()
                        * addr_is_not_zero.clone()
                        * (1.expr() - addr_unchange_next)
                        * (pc - length_cur - (BYTECODE_NUM_PADDING as u8 - 1).expr()),
                ),
                (
                    "addr_is_not_zero && is_padding_cur --> field_index = 1",
                    q_enable.clone()
                        * addr_is_not_zero.clone()
                        * is_padding_cur.clone()
                        * (field_index - 1.expr()),
                ),
                (
                    "addr_is_not_zero && is_padding_cur --> padding_shift = 256^(BYTES_IN_FIELD)",
                    q_enable.clone()
                        * addr_is_not_zero.clone()
                        * is_padding_cur.clone()
                        * (padding_shift
                            - 1.expr() * pow_of_two::<F>(8 * POSEIDON_HASH_BYTES_IN_FIELD)),
                ),
            ]
        });

        meta.create_gate("BYTECODE_all_zero_padding", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_padding_cur = meta.query_advice(config.is_padding, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_zero_prev = config.cnt_is_zero.expr_at(meta, Rotation::prev());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let acc_hi = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo = meta.query_advice(config.acc_lo, Rotation::cur());
            let is_high = meta.query_advice(config.is_high, Rotation::cur());
            let is_field_border =
                meta.query_advice(config.poseidon_aux_conf.is_field_border, Rotation::cur());
            let field_input =
                meta.query_advice(config.poseidon_aux_conf.field_input, Rotation::cur());
            let bytes_in_field_index = meta.query_advice(
                config.poseidon_aux_conf.bytes_in_field_index,
                Rotation::cur(),
            );

            // previous cnt is 0, and the current cnt is also 0, indicating that the current bytecode is not the byte of push
            let is_all_zero_padding = cnt_is_zero_prev * cnt_is_zero * is_padding_cur;
            vec![
                (
                    "bytecode is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * bytecode,
                ),
                (
                    "value_hi is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * value_hi,
                ),
                (
                    "value_lo is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * value_lo,
                ),
                (
                    "acc_hi is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * acc_hi,
                ),
                (
                    "acc_lo is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * acc_lo,
                ),
                (
                    "is_high is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * is_high,
                ),
                (
                    "is_field_border is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * is_field_border,
                ),
                (
                    "field_input is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * field_input,
                ),
                (
                    "bytes_in_field_index is zero",
                    q_enable.clone() * is_all_zero_padding.clone() * bytes_in_field_index,
                ),
            ]
        });

        meta.create_gate("BYTECODE_q_first_rows_constrains", |meta| {
            let q_first_rows = meta.query_selector(config.q_first_rows);
            let addr = meta.query_advice(config.addr, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let pc = meta.query_advice(config.pc, Rotation::cur());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let acc_lo = meta.query_advice(config.acc_lo, Rotation::cur());
            let is_high = meta.query_advice(config.is_high, Rotation::cur());
            let hash = meta.query_advice(config.poseidon_aux_conf.hash, Rotation::cur());
            let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
            let cnt_is_15 = config.cnt_is_15.expr();
            let addr_unchange = config.addr_unchange.expr();
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            let field_input =
                meta.query_advice(config.poseidon_aux_conf.field_input, Rotation::cur());
            let bytes_in_field_index = meta.query_advice(
                config.poseidon_aux_conf.bytes_in_field_index,
                Rotation::cur(),
            );
            let field_index =
                meta.query_advice(config.poseidon_aux_conf.field_index, Rotation::cur());
            let is_field_border =
                meta.query_advice(config.poseidon_aux_conf.is_field_border, Rotation::cur());
            let padding_shift =
                meta.query_advice(config.poseidon_aux_conf.padding_shift, Rotation::cur());

            vec![
                ("q_first_rows=1 => addr=0", q_first_rows.clone() * addr),
                ("q_first_rows=1 => pc=0", q_first_rows.clone() * pc),
                (
                    "q_first_rows=1 => bytecode=0",
                    q_first_rows.clone() * bytecode,
                ),
                (
                    "q_first_rows=1 => value_hi=0",
                    q_first_rows.clone() * value_hi,
                ),
                (
                    "q_first_rows=1 => value_lo=0",
                    q_first_rows.clone() * value_lo,
                ),
                ("q_first_rows=1 => acc_lo=0", q_first_rows.clone() * acc_lo),
                ("q_first_rows=1 ==> cnt=0", q_first_rows.clone() * cnt),
                (
                    "q_first_rows=1 => is_high=0",
                    q_first_rows.clone() * is_high,
                ),
                ("q_first_rows=1 => hash=0", q_first_rows.clone() * hash),
                (
                    "q_first_rows=1 => cnt_is_zero=1",
                    q_first_rows.clone() * (1.expr() - cnt_is_zero),
                ),
                (
                    "q_first_rows=1 => cnt_is_15=0",
                    q_first_rows.clone() * cnt_is_15,
                ),
                (
                    "q_first_rows=1 => addr_unchange=1",
                    q_first_rows.clone() * (1.expr() - addr_unchange),
                ),
                (
                    "q_first_rows=1 => addr_is_zero=1",
                    q_first_rows.clone() * (1.expr() - addr_is_zero.clone()),
                ),
                (
                    "q_first_rows=1 => field_input is zero",
                    q_first_rows.clone() * addr_is_zero.clone() * field_input,
                ),
                (
                    "q_first_rows=1 => bytes_in_field_index is zero",
                    q_first_rows.clone() * addr_is_zero.clone() * bytes_in_field_index,
                ),
                (
                    "q_first_rows=1 => field_index is one",
                    q_first_rows.clone() * addr_is_zero.clone() * (1.expr() - field_index),
                ),
                (
                    "q_first_rows=1 => is_field_border is zero",
                    q_first_rows.clone() * addr_is_zero.clone() * is_field_border,
                ),
                (
                    "q_first_rows=1 => padding_shift is 256^(BYTES_IN_FIELD)",
                    q_first_rows.clone()
                        * addr_is_zero.clone()
                        * (padding_shift
                            - 1.expr() * pow_of_two::<F>(8 * POSEIDON_HASH_BYTES_IN_FIELD)),
                ),
            ]
        });

        // Hash auxiliary column constraint
        config.configure_hash_aux(meta);

        // add all lookup constraints here
        // config.push_byte_range_lookup(meta, "BYTECODE_PUSH_BYTE_RANGE_LOOKUP");
        config.bytecode_lookup(meta, "BYTECODE_LOOKUP_FIXED");
        config.poseidon_lookup(meta, "BYTECODE_LOOKUP_POSEIDON_HASH");
        config.public_lookup(meta, "BYTECODE_LOOKUP_PUBLIC_CODE_HASH");

        config
    }
}

impl<F: Field> BytecodeHashAuxConfig<F> {
    fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let hash = meta.advice_column();
        let control_length = meta.advice_column();
        let field_input = meta.advice_column();
        let bytes_in_field_index = meta.advice_column();
        let bytes_in_field_inv = meta.advice_column();
        let is_field_border = meta.advice_column();
        let padding_shift = meta.advice_column();
        let field_index = meta.advice_column();
        let field_index_inv = meta.advice_column();
        let poseidon_aux_conf = BytecodeHashAuxConfig {
            hash,
            control_length,
            field_input,
            bytes_in_field_index,
            bytes_in_field_inv,
            is_field_border,
            padding_shift,
            field_index,
            field_index_inv,
            _marker: PhantomData,
        };

        poseidon_aux_conf
    }
}

impl<F: Field> BytecodeCircuitConfig<F> {
    fn configure_hash_aux(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("BYTECODE_field", |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let is_field_border =
                meta.query_advice(self.poseidon_aux_conf.is_field_border, Rotation::cur());
            vec![(
                "is_field_border is bool",
                q_enable * is_field_border.clone() * (1.expr() - is_field_border),
            )]
        });

        // current byte_in_field index is not the last one: i.e POSEIDON_HASH_BYTES_IN_FIELD
        // note: POSEIDON_HASH_BYTES_IN_FIELD is currently a constant.
        let q_byte_in_field_not_last = |meta: &mut VirtualCells<F>| {
            (POSEIDON_HASH_BYTES_IN_FIELD.expr()
                - meta.query_advice(self.poseidon_aux_conf.bytes_in_field_index, Rotation::cur()))
                * meta.query_advice(self.poseidon_aux_conf.bytes_in_field_inv, Rotation::cur())
        };

        meta.create_gate("BYTECODE_field_byte_cycling", |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let addr_is_not_zero = not::expr(self.addr_is_zero.expr_at(meta, Rotation::cur()));
            let is_padding = meta.query_advice(self.is_padding, Rotation::cur());
            let condition = q_enable * addr_is_not_zero * not::expr(is_padding);

            let field_input =
                meta.query_advice(self.poseidon_aux_conf.field_input, Rotation::cur());
            let file_input_prev =
                meta.query_advice(self.poseidon_aux_conf.field_input, Rotation::prev());
            let bytes_in_field_index =
                meta.query_advice(self.poseidon_aux_conf.bytes_in_field_index, Rotation::cur());
            let is_field_border =
                meta.query_advice(self.poseidon_aux_conf.is_field_border, Rotation::cur());
            let is_field_border_prev =
                meta.query_advice(self.poseidon_aux_conf.is_field_border, Rotation::prev());
            let bytes_in_field_index_prev = meta.query_advice(
                self.poseidon_aux_conf.bytes_in_field_index,
                Rotation::prev(),
            );
            let code = meta.query_advice(self.bytecode, Rotation::cur());
            let padding_shift =
                meta.query_advice(self.poseidon_aux_conf.padding_shift, Rotation::cur());
            let padding_shift_prev =
                meta.query_advice(self.poseidon_aux_conf.padding_shift, Rotation::prev());
            let shifted_byte = code * padding_shift.clone();
            let addr_unchange_next = self.addr_unchange_next.expr();
            let is_padding_next = meta.query_advice(self.is_padding, Rotation::next());

            vec![
                (
                    "q_byte_in_field_not_last = 1 except for BYTES_IN_FIELD",
                    condition.clone() *
                        (POSEIDON_HASH_BYTES_IN_FIELD.expr() - bytes_in_field_index.clone())
                        * (1.expr() - q_byte_in_field_not_last(meta)),
                ),
                (
                    // is_field_border = 1 时满足三个或条件:
                    // 1. q_byte_in_field_is_last index恰好在31的边缘，例如index=30，则表示为边缘，此时该值为1
                    // 2. 当没发生padding行时，恰好下一行为地址切换，此时也表示在边缘处，not::expr(addr_unchange_next) = 1
                    // 3. 下一行为padding行，此时index+1已经到达了code len的位置，is_padding_next = 1
                    "is_field_border := q_byte_in_field_is_last or addr_change_next or next_is_padding",
                    condition.clone() *
                        (is_field_border - or::expr(vec![
                            not::expr(q_byte_in_field_not_last(meta)),
                            not::expr(addr_unchange_next),
                            is_padding_next
                        ])),
                ),
                (
                    "byte_in_field_index := 1 if is_field_border_prev else (byte_in_field_index_prev + 1)",
                    condition.clone() *
                        (bytes_in_field_index - select::expr(
                            is_field_border_prev.clone(),
                            1.expr(),
                            bytes_in_field_index_prev + 1.expr(),
                        ))
                ),
                (
                    // 地址切换行不影响该约束
                    "field_input = byte * padding_shift if is_field_border_prev else field_input_prev + byte * padding_shift",
                    condition.clone() *
                        (field_input - select::expr(
                            is_field_border_prev.clone(),
                            shifted_byte.clone(),
                            file_input_prev + shifted_byte,
                        ))
                ),
                (
                    "when addr_unchange if not is_field_border_prev, then padding_shift := padding_shift_prev / 256",
                    condition.clone() *
                        not::expr(is_field_border_prev.clone()) *
                        (padding_shift.clone() * 256.expr() - padding_shift_prev)
                ),
                (
                    // 当地址切换时，也包含在如下情况里，因为地址切换时，is_field_border_prev == 1
                    "if is_field_border_prev padding_shift := 256^(BYTES_IN_FIELD-1)",
                    condition.clone() * is_field_border_prev * (padding_shift - 1.expr() * pow_of_two::<F>(8 * (POSEIDON_HASH_BYTES_IN_FIELD - 1)))
                ),
            ]
        });

        // current field index is not the last one of the input: i.e
        // PoseidonTable::INPUT_WIDTH
        let q_field_not_last = |meta: &mut VirtualCells<F>| {
            (PoseidonTable::INPUT_WIDTH.expr()
                - meta.query_advice(self.poseidon_aux_conf.field_index, Rotation::cur()))
                * meta.query_advice(self.poseidon_aux_conf.field_index_inv, Rotation::cur())
        };

        meta.create_gate("BYTECODE_field_input_cycling", |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let addr_is_not_zero = not::expr(self.addr_is_zero.expr_at(meta, Rotation::cur()));
            let is_padding = meta.query_advice(self.is_padding, Rotation::cur());
            let condition = q_enable * addr_is_not_zero * not::expr(is_padding);

            let field_index =
                meta.query_advice(self.poseidon_aux_conf.field_index, Rotation::cur());
            let field_index_prev =
                meta.query_advice(self.poseidon_aux_conf.field_index, Rotation::prev());
            let field_index_inv_prev =
                meta.query_advice(self.poseidon_aux_conf.field_index_inv, Rotation::prev());
            let is_field_border_prev =
                meta.query_advice(self.poseidon_aux_conf.is_field_border, Rotation::prev());
            let control_length = meta.query_advice(self.poseidon_aux_conf.control_length, Rotation::cur());
            let control_length_prev = meta.query_advice(self.poseidon_aux_conf.control_length, Rotation::prev());

            let code_length = meta.query_advice(self.length, Rotation::cur());
            let addr_unchange = self.addr_unchange.expr();

            let pc = meta.query_advice(self.pc, Rotation::cur());
            // 当q_input_continue = 1, 表示上一行还在input_0的行中
            let q_input_continue =
                (PoseidonTable::INPUT_WIDTH.expr() - field_index_prev.clone()) * field_index_inv_prev;
            // is_field_border_prev = 1 表示上一行为31边界位置；
            // not::expr(q_input_continue) = 1 表示上一行在input_1的行中；
            // 与条件之后，q_input_border_last = 1 表示上一行为input_1的边界位置
            let q_input_border_last =
                and::expr([is_field_border_prev.clone(), not::expr(q_input_continue)]);
            vec![
                (
                    "q_field_not_last = 1 except for PoseidonTable::INPUT_WIDTH",
                    condition.clone() *
                        (PoseidonTable::INPUT_WIDTH.expr() - field_index.clone())
                        * (1.expr() - q_field_not_last(meta))
                ),
                (
                    // 这里单独加了一个条件为addr_unchange，因为当发生地址切换时，q_input_border_last 取值为0或1
                    // 当为0时，此时control_length不可能等于code_length_prev，所以此时约束无法成立，故拆分处理
                    "addr_unchange => control_length := code_length - pc if q_input_border_last else control_length_prev",
                    condition.clone() * addr_unchange.clone() *
                        (control_length.clone() - select::expr(
                            q_input_border_last.clone(),
                            code_length.clone() - pc,
                            control_length_prev
                        ))
                ),
                (
                    "addr_change => control_length := code length",
                    condition.clone() * not::expr(addr_unchange.clone()) * (control_length - code_length)
                ),
                (
                    "field_index = 1 when q_input_border_last",
                    condition.clone() *
                        q_input_border_last.clone() * (1.expr() - field_index.clone())
                ),
                (
                    "when not q_input_border_last, field_index := if is_field_border_prev then field_index_prev + 1 else field_index_prev",
                    condition.clone() *
                        not::expr(q_input_border_last) * (field_index - select::expr(
                        is_field_border_prev,
                        field_index_prev.clone() + 1.expr(),
                        field_index_prev
                    ))
                )
            ]
        });
    }

    // assign data to circuit table cell
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row_cur: &Row,
        row_prev: Option<&Row>,
        row_next: Option<&Row>,
    ) -> Result<(), Error> {
        let cnt_is_zero = IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let cnt_is_15 = IsZeroChip::construct(self.cnt_is_15.clone());
        let addr_unchange = IsZeroChip::construct(self.addr_unchange.clone());
        let addr_unchange_next = IsZeroChip::construct(self.addr_unchange_next.clone());
        let addr_is_zero = IsZeroWithRotationChip::construct(self.addr_is_zero.clone());

        let prev_row_addr_value = row_prev
            .map(|x| x.addr.unwrap_or_default())
            .unwrap_or_default();
        let cur_row_addr_value = row_cur.addr.unwrap_or_default();
        let next_row_addr_value = row_next
            .map(|x| x.addr.unwrap_or_default())
            .unwrap_or_default();

        // assign value
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.bytecode.unwrap_or_default(),
            self.bytecode,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.addr.unwrap_or_default(),
            self.addr,
        )?;
        assign_advice_or_fixed_with_u256(region, offset, &row_cur.pc.unwrap_or_default(), self.pc)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.value_hi.unwrap_or_default(),
            self.value_hi,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.value_lo.unwrap_or_default(),
            self.value_lo,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.acc_hi.unwrap_or_default(),
            self.acc_hi,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.acc_lo.unwrap_or_default(),
            self.acc_lo,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.cnt.unwrap_or_default(),
            self.cnt,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.is_high.unwrap_or_default(),
            self.is_high,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.hash.unwrap_or_default(),
            self.poseidon_aux_conf.hash,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.length.unwrap_or_default(),
            self.length,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &row_cur.is_padding.unwrap_or_default(),
            self.is_padding,
        )?;

        let cnt_f =
            F::from_uniform_bytes(&convert_u256_to_64_bytes(&row_cur.cnt.unwrap_or_default()));
        cnt_is_zero.assign(region, offset, Value::known(cnt_f))?;
        cnt_is_15.assign(region, offset, Value::known(cnt_f - F::from(15)))?;
        addr_unchange.assign(
            region,
            offset,
            Value::known(
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&cur_row_addr_value))
                    - F::from_uniform_bytes(&convert_u256_to_64_bytes(&prev_row_addr_value)),
            ),
        )?;
        addr_unchange_next.assign(
            region,
            offset,
            Value::known(
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&next_row_addr_value))
                    - F::from_uniform_bytes(&convert_u256_to_64_bytes(&cur_row_addr_value)),
            ),
        )?;
        addr_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &cur_row_addr_value,
            ))),
        )?;
        Ok(())
    }

    /// 返回的row_input是为了作为下一轮的输入，每31轮拼成一个Fr或已经为该bytecode的最后一行则置为0；
    /// 满足：input = input_0 || ... || input_30，其中每个input为u8类型，通过padding_shift左移，将
    /// 这些u8类型的数拼成一个Fr(31个字节)，因为input_0是最高位，所以每次返回的row_input已经是一个31字节的Fr类型；
    /// 例如：对于input_1的这一轮，input_0则为input_prev，input_0 || input_1 组成高31和高30位，返回结果即为row_input,
    /// 作为下一轮的输入
    pub fn assign_poseidon_aux_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
        input_prev: F,
    ) -> Result<F, Error> {
        let code_length = row.length.unwrap_or_default().as_usize();
        let code_index = row.pc.unwrap_or_default().as_usize();
        let row_input = {
            let block_size = POSEIDON_HASH_BYTES_IN_FIELD * PoseidonTable::INPUT_WIDTH;
            let prog_block = code_index / block_size;
            let control_length = code_length - prog_block * block_size;
            // code_index+1是否恰好在31这个位置
            let bytes_in_field_index = (code_index + 1) % POSEIDON_HASH_BYTES_IN_FIELD;
            let field_border = bytes_in_field_index == 0;
            // 如果在边缘则为31，否则就是1..30
            let bytes_in_field_index = if field_border {
                POSEIDON_HASH_BYTES_IN_FIELD
            } else {
                bytes_in_field_index
            };
            let bytes_in_field_index_inv_f =
                F::from((POSEIDON_HASH_BYTES_IN_FIELD - bytes_in_field_index) as u64)
                    .invert()
                    .unwrap_or(F::zero());
            // 256 ^ (31 - bytes_in_field_index) => (31 - bytes_in_field_index) 范围是0..30
            let padding_shift_f =
                pow_of_two::<F>(8 * (POSEIDON_HASH_BYTES_IN_FIELD - bytes_in_field_index));
            // 是否左移只与value的index有关，input_prev初始是0
            // 比如index = 0， row.value * 256 ^ 30 + 0
            // index = 1, row.value * 256 ^ 29 + index_0 --> 0..30
            // 当index = 30, bytes_in_field_index = 31
            // row.value * 256 ^ 0 + index_29 之后次轮返回的input_f初始化为0，表示新的一轮循环
            // 所以相当于一个字节然后左移最大30位，其实就是一个31字节的大数，对应哈希表
            let input_f =
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.bytecode.unwrap_or_default()))
                    * padding_shift_f
                    + input_prev;
            // relax field_border for code end
            // 在31边缘和在code_length边缘都为边缘
            let field_border = field_border || code_index + 1 == code_length;

            // 判断在 0.. 30 还是 31.. 62 这个区间，区分 input_0 or input_1, 比如 0.. 30 结果都为 1，31.. 61 结果都为 2
            let field_index = (code_index % block_size) / POSEIDON_HASH_BYTES_IN_FIELD + 1;
            let field_index_inv_f = F::from((PoseidonTable::INPUT_WIDTH - field_index) as u64)
                .invert()
                .unwrap_or(F::zero());

            for (tip, column, val) in [
                (
                    "control length",
                    self.poseidon_aux_conf.control_length,
                    F::from(control_length as u64),
                ),
                ("field input", self.poseidon_aux_conf.field_input, input_f),
                (
                    "bytes in field",
                    self.poseidon_aux_conf.bytes_in_field_index,
                    F::from(bytes_in_field_index as u64),
                ),
                (
                    "bytes in field inv",
                    self.poseidon_aux_conf.bytes_in_field_inv,
                    bytes_in_field_index_inv_f,
                ),
                (
                    "field border",
                    self.poseidon_aux_conf.is_field_border,
                    F::from(field_border as u64),
                ),
                (
                    "padding shift",
                    self.poseidon_aux_conf.padding_shift,
                    padding_shift_f,
                ),
                (
                    "field index",
                    self.poseidon_aux_conf.field_index,
                    F::from(field_index as u64),
                ),
                (
                    "field index inv",
                    self.poseidon_aux_conf.field_index_inv,
                    field_index_inv_f,
                ),
            ] {
                region.assign_advice(
                    || format!("assign {tip} {offset}"),
                    column,
                    offset,
                    || Value::known(val),
                )?;
            }

            if field_border {
                F::zero()
            } else {
                input_f
            }
        };

        Ok(row_input)
    }

    pub fn assign_poseidon_aux_default_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.control_length,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.field_input,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.bytes_in_field_index,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.bytes_in_field_inv,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.is_field_border,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::from(256).pow(U256::from(POSEIDON_HASH_BYTES_IN_FIELD)),
            self.poseidon_aux_conf.padding_shift,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::one(),
            self.poseidon_aux_conf.field_index,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.poseidon_aux_conf.field_index_inv,
        )?;
        Ok(())
    }

    /// assign values from witness in a region, except for values copied from instance
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        _challenges: &Challenges<Value<F>>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        let bytecode_len = witness.bytecode.len();
        let default_row = Default::default();
        let mut row_input = F::zero();
        for offset in 0..bytecode_len {
            let row_prev = if offset == 0 {
                &default_row
            } else {
                &witness.bytecode[offset - 1]
            };

            let row_cur = &witness.bytecode[offset];
            let row_next = if offset == bytecode_len - 1 {
                &default_row
            } else {
                &witness.bytecode[offset + 1]
            };

            // if the `cur_row_addr_value - prev_row_addr_value` is 0, it means addr has not changed.
            // if the `cur_row_addr_value - prev_row_addr_value` is not 0, it means addr has changed, and it is a new contract.
            let row_cur_addr_value = row_cur.addr.unwrap_or_default();
            let row_prev_addr_value = row_prev.addr.unwrap_or_default();
            let addr_unchange_flag = row_cur_addr_value.cmp(&row_prev_addr_value).is_eq();
            let addr_is_zero_flag = row_cur_addr_value.is_zero();

            // assign_row
            self.assign_row(region, offset, row_cur, Some(row_prev), Some(row_next))?;

            let is_padding = row_cur.is_padding.unwrap_or_default() == U256::one();
            if is_padding || addr_is_zero_flag {
                self.assign_poseidon_aux_default_row(region, offset)?;
            } else {
                if !addr_unchange_flag {
                    row_input = F::zero()
                }
                row_input = self.assign_poseidon_aux_row(region, offset, row_cur, row_input)?;
            }
        }

        // pad the rest rows
        for offset in witness.bytecode.len()..num_row_incl_padding {
            let row_prev = if offset == witness.bytecode.len() {
                witness.bytecode.last()
            } else {
                None
            };
            self.assign_row(region, offset, &Default::default(), row_prev, None)?;
            self.assign_poseidon_aux_default_row(region, offset)?;
        }
        Ok(())
    }

    /// set the annotation information of the circuit colum
    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "BYTECODE_addr", self.addr);
        region.name_column(|| "BYTECODE_pc", self.pc);
        region.name_column(|| "BYTECODE_bytecode", self.bytecode);
        region.name_column(|| "BYTECODE_value_hi", self.value_hi);
        region.name_column(|| "BYTECODE_value_lo", self.value_lo);
        region.name_column(|| "BYTECODE_acc_hi", self.acc_hi);
        region.name_column(|| "BYTECODE_acc_lo", self.acc_lo);
        region.name_column(|| "BYTECODE_cnt", self.cnt);
        region.name_column(|| "BYTECODE_is_high", self.is_high);
        region.name_column(|| "BYTECODE_hash", self.poseidon_aux_conf.hash);
        region.name_column(
            || "BYTECODE_control_length",
            self.poseidon_aux_conf.control_length,
        );
        region.name_column(
            || "BYTECODE_field_input",
            self.poseidon_aux_conf.field_input,
        );
        region.name_column(
            || "BYTECODE_bytes_in_field_index",
            self.poseidon_aux_conf.bytes_in_field_index,
        );
        region.name_column(
            || "BYTECODE_bytes_in_field_inv",
            self.poseidon_aux_conf.bytes_in_field_inv,
        );
        region.name_column(
            || "BYTECODE_is_field_border",
            self.poseidon_aux_conf.is_field_border,
        );
        region.name_column(
            || "BYTECODE_padding_shift",
            self.poseidon_aux_conf.padding_shift,
        );
        region.name_column(
            || "BYTECODE_field_index",
            self.poseidon_aux_conf.field_index,
        );
        region.name_column(
            || "BYTECODE_field_index_inv",
            self.poseidon_aux_conf.field_index_inv,
        );
        self.cnt_is_zero
            .annotate_columns_in_region(region, "BYTECODE_cnt_is_zero");
        self.cnt_is_15
            .annotate_columns_in_region(region, "BYTECODE_cnt_is_15");
        self.addr_unchange
            .annotate_columns_in_region(region, "BYTECODE_addr_unchange");
        self.addr_is_zero
            .annotate_columns_in_region(region, "BYTECODE_addr_is_zero");
    }

    /// use Lookup to constrain the correctness of Push data.
    /// the data of PUSH instruction PUSH is bytes, so the range of a byte is 0~255.
    /// src: bytecode circuit, target: fixed circuit table
    pub fn push_byte_range_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any(name, |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let cnt_is_zero_prev = self.cnt_is_zero.expr_at(meta, Rotation::prev());
            let is_push_byte = 1.expr() - cnt_is_zero_prev;

            // construct Lookup entry of U8 type
            let fixed_entry = LookupEntry::U8(meta.query_advice(self.bytecode, Rotation::cur()));

            let fixed_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .fixed_table
                .get_lookup_vector(meta, fixed_entry.clone());

            fixed_lookup_vec
                .into_iter()
                .map(|(left, right)| (q_enable.clone() * is_push_byte.clone() * left, right))
                .collect()
        });
    }

    /// use Lookup to constrain the correctness of Opcode.
    /// src: bytecode circuit, target: fixed circuit table
    pub fn bytecode_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any(name, |meta| {
            use crate::witness::fixed;
            let q_enable = meta.query_selector(self.q_enable);
            let cnt_is_zero_prev = self.cnt_is_zero.expr_at(meta, Rotation::prev());
            let addr_is_zero = self.addr_is_zero.expr_at(meta, Rotation::cur());

            // note: the addr value of the padding row is 0, and the addr value of the Opcode instruction row is not 0
            // if the cnt value of the previous row is 0, it means that the current row is a Padding Row or a new Opcode instruction row,
            // so, the row of the Opcode instruction needs to satisfy that the cnt of the previous row is 0, and the addr of the current row is not 0.
            let is_opcode = cnt_is_zero_prev.clone() * (1.expr() - addr_is_zero);

            // construct Lookup entry of Fixed type
            let fixed_entry = LookupEntry::Fixed {
                tag: (fixed::Tag::Bytecode as u8).expr(),
                values: [
                    meta.query_advice(self.bytecode, Rotation::cur()), // bytecode
                    meta.query_advice(self.cnt, Rotation::cur()),
                    meta.query_advice(self.is_high, Rotation::cur()),
                ],
            };

            let fixed_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .fixed_table
                .get_lookup_vector(meta, fixed_entry.clone());

            fixed_lookup_vec
                .into_iter()
                .map(|(left, right)| (q_enable.clone() * is_opcode.clone() * left, right))
                .collect()
        });
    }

    pub fn poseidon_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        let field_selector = |meta: &mut VirtualCells<F>| {
            // 0表示input_0范围内，1表示input_1范围内
            let field_index =
                meta.query_advice(self.poseidon_aux_conf.field_index, Rotation::cur()) - 1.expr();
            [1.expr() - field_index.clone(), field_index]
        };

        let domain_spec_factor = Expression::Constant(F::from_u128(HASHABLE_DOMAIN_SPEC));

        // poseidon lookup:
        //  * PoseidonTable::INPUT_WIDTH lookups for each input field
        for i in 0..PoseidonTable::INPUT_WIDTH {
            meta.lookup_any(name, |meta| {
                // 用于判断是input_0的边界还是input_1的边界
                let enable = and::expr(vec![
                    meta.query_advice(self.poseidon_aux_conf.is_field_border, Rotation::cur()),
                    field_selector(meta)[i].clone(),
                ]);
                let q_enable = meta.query_selector(self.q_enable);
                let addr_is_not_zero = not::expr(self.addr_is_zero.expr_at(meta, Rotation::cur()));
                let condition = q_enable * addr_is_not_zero * enable;

                let poseidon_entry = LookupEntry::PoseidonWithSelector {
                    q_enable: 1.expr(),
                    hash_id: meta.query_advice(self.poseidon_aux_conf.hash, Rotation::cur()),
                    input: meta.query_advice(self.poseidon_aux_conf.field_input, Rotation::cur()),
                    control: meta
                        .query_advice(self.poseidon_aux_conf.control_length, Rotation::cur())
                        * domain_spec_factor.clone(),
                    domain: 0.expr(),
                    input_selector: i.expr(),
                };

                let poseidon_lookup_vec =
                    self.poseidon_table.get_lookup_vector(meta, poseidon_entry);
                poseidon_lookup_vec
                    .into_iter()
                    .map(|(left, right)| (condition.clone() * left, right))
                    .collect()
            });
        }
    }

    pub fn public_lookup(&self, meta: &mut ConstraintSystem<F>, name: &str) {
        meta.lookup_any(name, |meta| {
            let q_enable = meta.query_selector(self.q_enable);
            let addr_is_zero = self.addr_is_zero.expr_at(meta, Rotation::cur());
            let addr_is_not_zero = 1.expr() - addr_is_zero;
            let is_padding_cur = meta.query_advice(self.is_padding, Rotation::cur());
            let is_padding_next = meta.query_advice(self.is_padding, Rotation::next());
            let public_entry = LookupEntry::PublicMergeAddr {
                tag: (public::Tag::CodeHash as u8).expr(),
                block_tx_idx: 0.expr(),
                addr: meta.query_advice(self.addr, Rotation::cur()),
                value: meta.query_advice(self.poseidon_aux_conf.hash, Rotation::cur()),
            };

            let public_lookup_vec: Vec<(Expression<F>, Expression<F>)> = self
                .public_table
                .get_lookup_vector(meta, public_entry.clone());

            public_lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    (
                        q_enable.clone()
                            * addr_is_not_zero.clone()
                            * (1.expr() - is_padding_cur.clone())
                            * is_padding_next.clone()
                            * left,
                        right,
                    )
                })
                .collect()
        });
    }
}

#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for BytecodeCircuit<F, MAX_NUM_ROW> {
    type Config = BytecodeCircuitConfig<F>;
    type Cells = ();

    /// construct BytecodeCircuit by witness
    fn new_from_witness(witness: &Witness) -> Self {
        BytecodeCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }

    /// populate circuit data
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();

        layouter.assign_region(
            || "bytecode circuit",
            |mut region| {
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assign circuit table value
                config.assign_with_region(&mut region, challenges, &self.witness, MAX_NUM_ROW)?;

                // enable q_first_rows
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
        // Rotation in constrains has prev and but doesn't have next, so return 1,0
        (1, 1)
    }

    fn num_rows(witness: &Witness) -> usize {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        let len = witness.bytecode.len();
        // Check that total number of rows in this sub circuit does not exceed max number of row (a super circuit level parameter)
        assert!(
            num_padding_begin + len + num_padding_end <= MAX_NUM_ROW,
            "begin padding {} + CODELEN {} + end padding {} > MAX_NUM_ROW {} (consider increase parameter MAX_NUM_ROW)",
            num_padding_begin,
            len,
            num_padding_end,
            MAX_NUM_ROW
        );

        num_padding_begin + len + num_padding_end
    }
}

/// test code
#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
    use crate::poseidon_circuit::{
        PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs, HASH_BLOCK_STEP_SIZE,
    };
    use crate::public_circuit::{PublicCircuit, PublicCircuitConfig, PublicCircuitConfigArgs};
    use crate::table::KeccakTable;
    use crate::util::{chunk_data_test, hash_code_poseidon, log2_ceil};
    use crate::witness::poseidon::{
        get_hash_input_from_u8s_default, get_poseidon_row_from_stream_input,
    };
    use crate::witness::public::Tag;
    use eth_types::evm_types::OpcodeId;
    use eth_types::Bytecode;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::{CircuitGates, MockProver};
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct BytecodeTestCircuitConfig<F: Field> {
        pub bytecode_circuit: BytecodeCircuitConfig<F>,
        pub public_circuit: PublicCircuitConfig<F>,
        // used to verify Lookup(src: Bytecode circuit, target: Fixed circuit table)
        pub fixed_circuit: FixedCircuitConfig<F>,
        pub poseidon_circuit: PoseidonCircuitConfig<F>,
        pub challenges: Challenges,
    }

    impl<F: Field> SubCircuitConfig<F> for BytecodeTestCircuitConfig<F> {
        type ConfigArgs = ();

        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            // construct instance column
            #[cfg(not(feature = "no_public_hash"))]
            let instance_hash = PublicTable::construct_hash_instance_column(meta);
            #[cfg(not(feature = "no_public_hash"))]
            let q_enable_public = meta.complex_selector();

            // initialize columns
            let q_enable_bytecode = meta.complex_selector();
            let q_enable_public = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let fixed_table = FixedTable::construct(meta);
            let poseidon_table = PoseidonTable::construct(meta);
            let public_table = PublicTable::construct(meta);
            // challenge
            let challenges = Challenges::construct(meta);
            // construct fixed circuit
            let fixed_circuit =
                FixedCircuitConfig::new(meta, FixedCircuitConfigArgs { fixed_table });

            // construct bytecode circuit
            let bytecode_circuit = BytecodeCircuitConfig::new(
                meta,
                BytecodeCircuitConfigArgs {
                    q_enable: q_enable_bytecode,
                    bytecode_table,
                    fixed_table,
                    poseidon_table,
                    public_table,
                    challenges,
                },
            );

            let poseidon_circuit =
                PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table });

            let keccak_table = KeccakTable::construct(meta);

            // todo 目前这个public hash是keccak特性，后面会优化
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

            // construct BytecodeTestCircuitConfig
            Self {
                fixed_circuit,
                bytecode_circuit,
                poseidon_circuit,
                public_circuit,
                challenges,
            }
        }
    }

    /// A standalone circuit for testing
    #[derive(Clone, Default, Debug)]
    pub struct BytecodeTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW>,
        pub fixed_circuit: FixedCircuit<F>,
        pub public_circuit: PublicCircuit<F, MAX_NUM_ROW>,
        pub poseidon_circuit: PoseidonCircuit<F, MAX_NUM_ROW>,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for BytecodeTestCircuit<F, MAX_NUM_ROW> {
        type Config = BytecodeTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config::new(meta, ())
        }

        /// populate BytecodeTestCircuit data
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

            // when feature `no_fixed_lookup` is on, we don't do synthesize
            #[cfg(not(feature = "no_fixed_lookup"))]
            self.fixed_circuit
                .synthesize_sub(&config.fixed_circuit, &mut layouter, &challenges)?;

            self.poseidon_circuit.synthesize_sub(
                &config.poseidon_circuit,
                &mut layouter,
                &challenges,
            )?;

            self.public_circuit.synthesize_sub(
                &config.public_circuit,
                &mut layouter,
                &challenges,
            )?;

            Ok(())
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> BytecodeTestCircuit<F, MAX_NUM_ROW> {
        /// construct BytecodeTestCircuit by witness
        pub fn new(witness: Witness) -> Self {
            Self {
                bytecode_circuit: BytecodeCircuit::new_from_witness(&witness),
                fixed_circuit: FixedCircuit::new_from_witness(&witness),
                poseidon_circuit: PoseidonCircuit::new_from_witness(&witness),
                public_circuit: PublicCircuit::new_from_witness(&witness),
            }
        }

        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bytecode_circuit.instance());
            vec.extend(self.fixed_circuit.instance());
            vec.extend(self.poseidon_circuit.instance());
            vec.extend(self.public_circuit.instance());
            vec
        }
    }

    fn test_bytecode_circuit(witness: Witness) -> MockProver<Fr> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = BytecodeTestCircuit::<Fr, MAX_NUM_ROW>::new(witness.clone());
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover
    }

    /// use simple bytecode to verify the correctness of Bytecode circuit constraints
    #[test]
    fn two_simple_contract() {
        // addr: 0x25556666, bytecode: 0x6001600100
        // bytecode:
        // PUSH1 0x00
        // PUSH1 0x00
        // STOP

        // addr: 0x66668888, bytecode: 00
        // bytecode:
        // STOP
        let addr1 = "0x25556666";
        let addr2 = "0x66668888";
        let contract1_bytecode = hex::decode("6000600000").unwrap();
        let contract2_bytecode = hex::decode("00").unwrap();

        let contract1_bytecode_len = contract1_bytecode.len();
        let contract2_bytecode_len = contract2_bytecode.len();

        let contract1_bytecode_hash = hash_code_poseidon(contract1_bytecode.as_slice());
        let contract2_bytecode_hash = hash_code_poseidon(contract2_bytecode.as_slice());

        // ========= contract 1 ========
        let mut pc = 0;
        let mut contract1_byte_rows = vec![];
        contract1_byte_rows.push(Row {
            addr: Some(addr1.into()),
            pc: Some(pc.into()),
            bytecode: Some(OpcodeId::PUSH1.as_u8().into()),
            cnt: Some(1.into()),
            hash: Some(contract1_bytecode_hash),
            length: Some(contract1_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        contract1_byte_rows.push(Row {
            addr: Some(addr1.into()),
            pc: Some(pc.into()),
            hash: Some(contract1_bytecode_hash),
            length: Some(contract1_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        contract1_byte_rows.push(Row {
            addr: Some(addr1.into()),
            pc: Some(pc.into()),
            bytecode: Some(OpcodeId::PUSH1.as_u8().into()),
            cnt: Some(1.into()),
            hash: Some(contract1_bytecode_hash),
            length: Some(contract1_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        contract1_byte_rows.push(Row {
            addr: Some(addr1.into()),
            pc: Some(pc.into()),
            hash: Some(contract1_bytecode_hash),
            length: Some(contract1_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        contract1_byte_rows.push(Row {
            addr: Some(addr1.into()),
            pc: Some(pc.into()),
            bytecode: Some(OpcodeId::STOP.as_u8().into()),
            hash: Some(contract1_bytecode_hash),
            length: Some(contract1_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        // padding row
        for _ in 0..BYTECODE_NUM_PADDING - (pc - contract1_bytecode.len()) {
            contract1_byte_rows.push(Row {
                addr: Some(addr1.into()),
                pc: Some(pc.into()),
                hash: Some(contract1_bytecode_hash),
                length: Some(contract1_bytecode_len.into()),
                is_padding: Some(U256::one()),
                ..Default::default()
            });
            pc += 1;
        }

        // ========= contract 2 ========
        pc = 0;
        let mut contract2_byte_rows = vec![];
        contract2_byte_rows.push(Row {
            addr: Some(addr2.into()),
            pc: Some(pc.into()),
            bytecode: Some(OpcodeId::STOP.as_u8().into()),
            hash: Some(contract2_bytecode_hash),
            length: Some(contract2_bytecode_len.into()),
            ..Default::default()
        });
        pc += 1;

        for _ in 0..BYTECODE_NUM_PADDING - (pc - contract2_bytecode.len()) {
            contract2_byte_rows.push(Row {
                addr: Some(addr2.into()),
                pc: Some(pc.into()),
                hash: Some(contract2_bytecode_hash),
                length: Some(contract2_bytecode_len.into()),
                is_padding: Some(U256::one()),
                ..Default::default()
            });
            pc += 1;
        }

        let addr1_u256: U256 = addr1.into();
        let addr2_u256: U256 = addr2.into();
        let addr1_hi = addr1_u256 >> 128;
        let addr1_lo = U256::from(addr1_u256.low_u128());
        let addr2_hi = addr2_u256 >> 128;
        let addr2_lo = U256::from(addr2_u256.low_u128());

        let mut public_rows = vec![];
        public_rows.push(public::Row {
            tag: Tag::CodeHash,
            value_0: Some(addr1_hi),
            value_1: Some(addr1_lo),
            value_2: Some(contract1_bytecode_hash),
            ..Default::default()
        });

        public_rows.push(public::Row {
            tag: Tag::CodeHash,
            value_0: Some(addr2_hi),
            value_1: Some(addr2_lo),
            value_2: Some(contract2_bytecode_hash),
            ..Default::default()
        });

        // construct Witness object
        let mut witness: Witness = Default::default();

        // begin padding
        (0..BytecodeCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| witness.bytecode.insert(0, Default::default()));
        (0..PublicCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| witness.public.insert(0, Default::default()));

        // push row
        witness.bytecode.extend(contract1_byte_rows);
        witness.bytecode.extend(contract2_byte_rows);
        witness.public.extend(public_rows);

        let unrolled_inputs =
            get_hash_input_from_u8s_default::<Fr>(contract1_bytecode.iter().copied());
        let mut poseidon_rows = get_poseidon_row_from_stream_input(
            &unrolled_inputs,
            None,
            contract1_bytecode.len() as u64,
            HASH_BLOCK_STEP_SIZE,
        );

        let unrolled_inputs =
            get_hash_input_from_u8s_default::<Fr>(contract2_bytecode.iter().copied());

        poseidon_rows.append(&mut get_poseidon_row_from_stream_input(
            &unrolled_inputs,
            None,
            contract2_bytecode.len() as u64,
            HASH_BLOCK_STEP_SIZE,
        ));

        witness.poseidon = poseidon_rows;

        #[cfg(not(feature = "no_public_hash"))]
        public::witness_post_handle(&mut witness);

        // verification circuit
        let prover = test_bytecode_circuit(witness);
        prover.assert_satisfied();
    }

    /// verify Push operation
    #[test]
    #[cfg(feature = "evm")]
    fn push_30() {
        // should be 1..=32
        let x = 30;
        let mut bytecode = Bytecode::default();
        bytecode.push(x, u128::MAX);

        // get machine code and generate trace by machine code
        let machine_code = bytecode.code();
        let trace = trace_parser::trace_program(&machine_code, &[]);

        // construct Witness object
        let witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        // verification circuit
        let prover = test_bytecode_circuit(witness);
        prover.assert_satisfied();
    }

    /// verify the correctness of the data in the generated Bytecode table
    #[test]
    #[cfg(feature = "evm")]
    fn push_30_fuzzing() {
        // should be 1..=32
        let x = 30;
        let mut bytecode = Bytecode::default();
        bytecode.push(x, u128::MAX);

        // get machine code and generate trace by machine code
        let machine_code = bytecode.code();
        let trace = trace_parser::trace_program(&machine_code, &[]);

        // construct Witness object
        let witness = Witness::new(&chunk_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        // manually verify data correctness
        {
            let mut witness = witness.clone();
            witness.bytecode[1].value_hi = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].value_lo = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].acc_hi = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].acc_lo = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].cnt = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    #[ignore]
    fn print_gates_lookups() {
        let gates = CircuitGates::collect::<Fr, BytecodeTestCircuit<Fr, MAX_NUM_ROW>>(());
        let str = gates.queries_to_csv();
        for line in str.lines() {
            let last_csv = line.rsplitn(2, ',').next().unwrap();
            println!("{}", last_csv);
        }
    }
}
