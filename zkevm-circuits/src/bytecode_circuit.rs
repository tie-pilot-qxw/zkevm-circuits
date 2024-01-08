use crate::table::{BytecodeTable, FixedTable, LookupEntry};
use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes, SubCircuit, SubCircuitConfig};
use crate::witness::bytecode::Row;
use crate::witness::{fixed, Witness};
use eth_types::{Field, U256};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::is_zero_with_rotation::{IsZeroWithRotationChip, IsZeroWithRotationConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use std::iter::zip;
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
/// +-------------+-------------------+------+----+----------+----------+----------+--------+--------+-----+---------+--------------+-----------+---------------+--------------+
/// |instance_addr| instance_bytecode | addr | pc | bytecode | value_hi | value_lo | acc_hi | acc_lo | cnt | is_high | cnt_is_zero  | cnt_is_15 | addr_unchange | addr_is_zero |
/// +-------------+-------------------+------+----+----------+----------+----------+--------+-------+-----+---------+--------------+------------+---------------+--------------+
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
#[derive(Clone)]
pub struct BytecodeCircuitConfig<F> {
    q_enable: Selector,
    /// the contract address of the bytecodes. public input
    instance_addr: Column<Instance>,
    /// bytecode, operation code or pushed value. public input
    instance_bytecode: Column<Instance>,
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
    /// for chip to determine whether cnt is 0
    cnt_is_zero: IsZeroWithRotationConfig<F>,
    /// for chip to determine whether cnt is 15
    cnt_is_15: IsZeroConfig<F>,
    /// for chip to check if addr is changed from previous row
    addr_unchange: IsZeroConfig<F>,
    /// for chip to check if addr is zero, which means the row is padding
    addr_is_zero: IsZeroWithRotationConfig<F>,
    // table used for lookup
    fixed_table: FixedTable,
}

pub struct BytecodeCircuitConfigArgs<F> {
    pub q_enable: Selector,
    pub bytecode_table: BytecodeTable<F>,
    pub fixed_table: FixedTable,
    pub instance_addr: Column<Instance>,
    pub instance_bytecode: Column<Instance>,
}

impl<F: Field> SubCircuitConfig<F> for BytecodeCircuitConfig<F> {
    type ConfigArgs = BytecodeCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            bytecode_table,
            fixed_table,
            instance_addr,
            instance_bytecode,
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

        // initialize columns
        let acc_hi = meta.advice_column();
        let acc_lo = meta.advice_column();
        let is_high = meta.advice_column();
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
        let addr_is_zero =
            IsZeroWithRotationChip::configure(meta, |meta| meta.query_selector(q_enable), addr);
        // we need to copy (equality) from public input to advice column
        meta.enable_equality(instance_addr);
        meta.enable_equality(addr);
        meta.enable_equality(instance_bytecode);
        meta.enable_equality(bytecode);

        // construct config object
        let config = Self {
            q_enable,
            instance_addr,
            instance_bytecode,
            addr,
            pc,
            bytecode,
            value_hi,
            value_lo,
            acc_hi,
            acc_lo,
            cnt,
            is_high,
            cnt_is_zero,
            cnt_is_15,
            addr_unchange,
            addr_is_zero,
            fixed_table,
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
                q_enable
                    * ((1.expr() - addr_unchange.clone()) * pc_cur.clone()
                        + addr_unchange
                            * (1.expr() - addr_is_zero) // this row is not padding
                            * (pc_cur - pc_prev - 1.expr())),
            ]
        });

        // constrain padding row, the padding row values are all 0
        // note: the data in the padding row has no actual meaning, it is just to make up the number of rows in the table
        meta.create_gate("BYTECODE_padding_is_zero", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let addr_is_zero = config.addr_is_zero.expr_at(meta, Rotation::cur());
            let addr = meta.query_advice(config.addr, Rotation::cur());
            let pc = meta.query_advice(config.pc, Rotation::cur());
            let bytecode = meta.query_advice(config.bytecode, Rotation::cur());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let acc_hi = meta.query_advice(config.acc_hi, Rotation::cur());
            let acc_lo = meta.query_advice(config.acc_lo, Rotation::cur());
            let cnt = meta.query_advice(config.cnt, Rotation::cur());
            let is_high = meta.query_advice(config.is_high, Rotation::cur());
            vec![
                q_enable.clone() * addr_is_zero.clone() * addr,
                q_enable.clone() * addr_is_zero.clone() * pc,
                q_enable.clone() * addr_is_zero.clone() * bytecode,
                q_enable.clone() * addr_is_zero.clone() * value_hi,
                q_enable.clone() * addr_is_zero.clone() * value_lo,
                q_enable.clone() * addr_is_zero.clone() * acc_hi,
                q_enable.clone() * addr_is_zero.clone() * acc_lo,
                q_enable.clone() * addr_is_zero.clone() * cnt,
                q_enable * addr_is_zero * is_high,
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
                q_enable.clone() * is_push_byte.clone() * (cnt_prev - cnt_cur - 1.expr()),
                // when cnt >=16, is_high is 1, and when cnt <16, is_high is 0
                q_enable.clone()
                    * is_push_byte.clone()
                    * (is_high_prev - is_high_cur.clone() - cnt_is_15),
                q_enable.clone() * is_push_byte.clone() * (value_hi_cur.clone() - value_hi_prev),
                q_enable.clone() * is_push_byte.clone() * (value_lo_cur.clone() - value_lo_prev),
                // cnt >= 16 ==> acc_hi = acc_hi_prev*256 + bytecode
                // cnt < 16 ==> acc_hi = acc_hi_prev
                q_enable.clone()
                    * is_push_byte.clone()
                    * (acc_hi_prev.clone()
                        + is_high_cur.clone() * (255.expr() * acc_hi_prev + bytecode.clone())
                        - acc_hi_cur.clone()),
                // cnt >= 16 ==> acc_lo=0, acc_lo = acc_lo_prev
                // cnt < 16 ==> acc_lo=acc_lo_prev*256 + bytecode
                q_enable.clone() * is_push_byte.clone() * is_high_cur.clone() * acc_lo_cur.clone(),
                q_enable.clone()
                    * is_push_byte.clone()
                    * (acc_lo_prev.clone()
                        + (1.expr() - is_high_cur.clone()) * (255.expr() * acc_lo_prev + bytecode)
                        - acc_lo_cur.clone()),
                // the last byte of push, value_hi=acc_hi, value_lo=acc_lo
                q_enable.clone() * is_push_last_byte.clone() * (value_hi_cur - acc_hi_cur),
                q_enable * is_push_last_byte.clone() * (value_lo_cur - acc_lo_cur),
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
                q_enable.clone() * opcode_is_no_push.clone() * value_hi,
                q_enable.clone() * opcode_is_no_push.clone() * value_lo,
                q_enable.clone() * opcode_is_no_push.clone() * acc_hi,
                q_enable.clone() * opcode_is_no_push.clone() * acc_lo,
                q_enable.clone() * opcode_is_no_push.clone() * is_high,
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
                q_enable.clone() * opcode_is_push.clone() * acc_hi_cur,
                q_enable.clone() * opcode_is_push.clone() * acc_lo_cur,
            ]
        });

        // add all lookup constraints here
        // config.push_byte_range_lookup(meta, "BYTECODE_PUSH_BYTE_RANGE_LOOKUP");
        config.bytecode_lookup(meta, "BYTECODE_LOOKUP");

        config
    }
}

impl<F: Field> BytecodeCircuitConfig<F> {
    // assign data to circuit table cell
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row_cur: &Row,
        row_prev: Option<&Row>,
    ) -> Result<(), Error> {
        let cnt_is_zero = IsZeroWithRotationChip::construct(self.cnt_is_zero.clone());
        let cnt_is_15 = IsZeroChip::construct(self.cnt_is_15.clone());
        let addr_unchange = IsZeroChip::construct(self.addr_unchange.clone());
        let addr_is_zero = IsZeroWithRotationChip::construct(self.addr_is_zero.clone());

        assign_advice_or_fixed(region, offset, &row_cur.pc.unwrap_or_default(), self.pc)?;
        assign_advice_or_fixed(
            region,
            offset,
            &row_cur.value_hi.unwrap_or_default(),
            self.value_hi,
        )?;
        assign_advice_or_fixed(
            region,
            offset,
            &row_cur.value_lo.unwrap_or_default(),
            self.value_lo,
        )?;
        assign_advice_or_fixed(
            region,
            offset,
            &row_cur.acc_hi.unwrap_or_default(),
            self.acc_hi,
        )?;
        assign_advice_or_fixed(
            region,
            offset,
            &row_cur.acc_lo.unwrap_or_default(),
            self.acc_lo,
        )?;
        assign_advice_or_fixed(region, offset, &row_cur.cnt.unwrap_or_default(), self.cnt)?;
        assign_advice_or_fixed(
            region,
            offset,
            &row_cur.is_high.unwrap_or_default(),
            self.is_high,
        )?;
        cnt_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row_cur.cnt.unwrap_or_default(),
            ))),
        )?;
        cnt_is_15.assign(
            region,
            offset,
            Value::known(
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row_cur.cnt.unwrap_or_default()))
                    - F::from(15),
            ),
        )?;
        addr_unchange.assign(
            region,
            offset,
            Value::known(
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row_cur.addr.unwrap_or_default()))
                    - F::from_uniform_bytes(&convert_u256_to_64_bytes(
                        &row_prev
                            .map(|x| x.addr.unwrap_or_default())
                            .unwrap_or_default(),
                    )),
            ),
        )?;
        addr_is_zero.assign(
            region,
            offset,
            Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                &row_cur.addr.unwrap_or_default(),
            ))),
        )?;
        Ok(())
    }

    /// assign values from witness in a region, except for values copied from instance
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // assign the first row
        self.assign_row(
            region,
            0,
            witness
                .bytecode
                .first()
                .expect("bytecode must have first row"),
            None,
        )?;
        // assign the rest rows
        for (offset, (row_cur, row_prev)) in
            zip(witness.bytecode.iter().skip(1), witness.bytecode.iter()).enumerate()
        {
            let offset = offset + 1;
            self.assign_row(region, offset, row_cur, Some(row_prev))?;
        }
        // pad the first row
        self.assign_row(
            region,
            witness.bytecode.len(),
            &Default::default(),
            witness.bytecode.last(),
        )?;
        // pad the rest rows
        for offset in witness.bytecode.len() + 1..num_row_incl_padding {
            self.assign_row(region, offset, &Default::default(), None)?;
        }
        Ok(())
    }

    /// assign values copied from instance
    pub fn assign_from_instance_with_region(
        &self,
        region: &mut Region<'_, F>,
        num_padding_begin: usize,
        max_codesize: usize,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // assign padding rows
        for offset in 0..num_padding_begin {
            assign_advice_or_fixed(region, offset, &U256::zero(), self.addr)?;
            assign_advice_or_fixed(region, offset, &U256::zero(), self.bytecode)?;
        }
        // use permutation to copy bytecode from instance to advice
        for offset in 0..max_codesize {
            // not padding, we use permutation constraint to copy addr and bytecode from instance
            // although this is inside synthesize(), this add constraints to the system
            region.assign_advice_from_instance(
                || "addr",
                self.instance_addr,
                offset,
                self.addr,
                num_padding_begin + offset,
            )?;
            region.assign_advice_from_instance(
                || "bytecode",
                self.instance_bytecode,
                offset,
                self.bytecode,
                num_padding_begin + offset,
            )?;
        }
        for offset in num_padding_begin + max_codesize..num_row_incl_padding {
            assign_advice_or_fixed(region, offset, &U256::zero(), self.addr)?;
            assign_advice_or_fixed(region, offset, &U256::zero(), self.bytecode)?;
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
}

#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field, const MAX_NUM_ROW: usize, const MAX_CODESIZE: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize, const MAX_CODESIZE: usize> SubCircuit<F>
    for BytecodeCircuit<F, MAX_NUM_ROW, MAX_CODESIZE>
{
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
        let (num_padding_begin, _num_padding_end) = Self::unusable_rows();
        let mut vec_addr: Vec<F> = self
            .witness
            .bytecode
            .iter()
            .skip(num_padding_begin)
            .map(|row| {
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.addr.unwrap_or_default()))
            })
            .collect();
        let mut vec_bytecode: Vec<F> = self
            .witness
            .bytecode
            .iter()
            .skip(num_padding_begin)
            .map(|row| {
                F::from_uniform_bytes(&convert_u256_to_64_bytes(&row.bytecode.unwrap_or_default()))
            })
            .collect();
        if vec_bytecode.len() > MAX_CODESIZE {
            panic!(
                "bytecode instance length {} > MAX_CODESIZE {} (consider increase parameter MAX_CODESIZE)",
                vec_bytecode.len(),
                MAX_CODESIZE
            );
        }
        // padding 0 to the end
        for _ in vec_bytecode.len()..MAX_CODESIZE {
            vec_addr.push(F::ZERO);
            vec_bytecode.push(F::ZERO);
        }
        vec![vec_addr, vec_bytecode]
    }

    /// populate circuit data
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "bytecode circuit",
            |mut region| {
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assgin circuit table value
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;
                config.assign_from_instance_with_region(
                    &mut region,
                    num_padding_begin,
                    MAX_CODESIZE,
                    MAX_NUM_ROW,
                )?;

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
        (1, 0)
    }

    fn num_rows(_witness: &Witness) -> usize {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        // Check that total number of rows in this subcircuit does not exceed max number of row (a super circuit level parameter)
        assert!(
            num_padding_begin + MAX_CODESIZE + num_padding_end <= MAX_NUM_ROW,
            "begin padding {} + MAX_CODESIZE {} + end padding {} > MAX_NUM_ROW {} (consider increase parameter MAX_NUM_ROW)",
            num_padding_begin,
            MAX_CODESIZE,
            num_padding_end,
            MAX_NUM_ROW
        );
        // Max bytecode witness length (a fixed parameter) plus must-have padding in the beginning and end
        // Not using the real bytecode witness length since the real bytecode witness will be padded to max length
        num_padding_begin + MAX_CODESIZE + num_padding_end
    }
}

/// test code
#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::{MAX_CODESIZE, MAX_NUM_ROW};
    use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
    use crate::util::{geth_data_test, log2_ceil};
    use eth_types::evm_types::OpcodeId;
    use eth_types::Bytecode;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::{CircuitGates, MockProver};
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct BytecodeTestCircuitConfig<F: Field> {
        pub bytecode_circuit: BytecodeCircuitConfig<F>,
        // used to verify Lookup(src: Bytecode circuit, target: Fixed circuit table)
        pub fixed_circuit: FixedCircuitConfig<F>,
    }

    impl<F: Field> SubCircuitConfig<F> for BytecodeTestCircuitConfig<F> {
        type ConfigArgs = ();

        fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
            // initialize columns
            let q_enable_bytecode = meta.complex_selector();
            let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
            let fixed_table = FixedTable::construct(meta);
            let (instance_addr, instance_bytecode) =
                BytecodeTable::construct_addr_bytecode_instance_column(meta);

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
                    instance_addr,
                    instance_bytecode,
                },
            );

            // construct BytecodeTestCircuitConfig
            Self {
                fixed_circuit,
                bytecode_circuit,
            }
        }
    }

    /// A standalone circuit for testing
    #[derive(Clone, Default, Debug)]
    pub struct BytecodeTestCircuit<F: Field> {
        pub bytecode_circuit: BytecodeCircuit<F, MAX_NUM_ROW, MAX_CODESIZE>,
        pub fixed_circuit: FixedCircuit<F>,
    }

    impl<F: Field> Circuit<F> for BytecodeTestCircuit<F> {
        type Config = BytecodeTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

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
            self.bytecode_circuit
                .synthesize_sub(&config.bytecode_circuit, &mut layouter)?;

            // when feature `no_fixed_lookup` is on, we don't do synthesize
            #[cfg(not(feature = "no_fixed_lookup"))]
            self.fixed_circuit
                .synthesize_sub(&config.fixed_circuit, &mut layouter)?;

            Ok(())
        }
    }

    impl<F: Field> BytecodeTestCircuit<F> {
        /// construct BytecodeTestCircuit by witness
        pub fn new(witness: Witness) -> Self {
            Self {
                bytecode_circuit: BytecodeCircuit::new_from_witness(&witness),
                fixed_circuit: FixedCircuit::new_from_witness(&witness),
            }
        }

        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.bytecode_circuit.instance());
            vec.extend(self.fixed_circuit.instance());
            vec
        }
    }

    fn test_bytecode_circuit(witness: Witness) -> MockProver<Fr> {
        let (num_padding_begin, _num_padding_end) =
            BytecodeCircuit::<Fr, MAX_NUM_ROW, MAX_CODESIZE>::unusable_rows();
        let mut witness = witness;
        // insert padding rows (rows with all 0)
        for _ in 0..num_padding_begin {
            witness.bytecode.insert(0, Default::default());
        }

        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = BytecodeTestCircuit::<Fr>::new(witness.clone());
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover
    }

    /// use simple bytecode to verify the correctness of Bytecode circuit constraints
    #[test]
    fn two_simple_contract() {
        // construct Bytecode table row
        let row1 = Row {
            addr: Some("0x25556666".into()),
            bytecode: Some(OpcodeId::PUSH1.as_u8().into()),
            cnt: Some(1.into()),
            ..Default::default()
        };
        let row2 = Row {
            addr: Some("0x25556666".into()),
            pc: Some(1.into()),
            ..Default::default()
        };
        let row3 = Row {
            addr: Some("0x25556666".into()),
            pc: Some(2.into()),
            bytecode: Some(OpcodeId::PUSH1.as_u8().into()),
            cnt: Some(1.into()),
            ..Default::default()
        };
        let row4 = Row {
            addr: Some("0x25556666".into()),
            pc: Some(3.into()),
            ..Default::default()
        };
        let row5 = Row {
            addr: Some("0x25556666".into()),
            pc: Some(4.into()),
            bytecode: Some(OpcodeId::STOP.as_u8().into()),
            ..Default::default()
        };
        let row6 = Row {
            addr: Some("0x66668888".into()),
            pc: Some(0.into()),
            bytecode: Some(OpcodeId::STOP.as_u8().into()),
            ..Default::default()
        };

        // construct Witness object
        let witness = Witness {
            bytecode: vec![row1, row2, row3, row4, row5, row6],
            ..Default::default()
        };

        // verification circuit
        let prover = test_bytecode_circuit(witness);
        prover.assert_satisfied_par();
    }

    /// verify Push operation
    #[test]
    fn push_30() {
        // should be 1..=32
        let x = 30;
        let mut bytecode = Bytecode::default();
        bytecode.push(x, u128::MAX);

        // get machine code and generate trace by machine code
        let machine_code = bytecode.code();
        let trace = trace_parser::trace_program(&machine_code, &[]);

        // construct Witness object
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        // verification circuit
        let prover = test_bytecode_circuit(witness);
        prover.assert_satisfied_par();
    }

    /// verify the correctness of the data in the generated Bytecode table
    #[test]
    fn push_30_fuzzing() {
        // should be 1..=32
        let x = 30;
        let mut bytecode = Bytecode::default();
        bytecode.push(x, u128::MAX);

        // get machine code and generate trace by machine code
        let machine_code = bytecode.code();
        let trace = trace_parser::trace_program(&machine_code, &[]);

        // construct Witness object
        let witness = Witness::new(&geth_data_test(
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
            assert!(prover.verify_par().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].value_lo = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify_par().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].acc_hi = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify_par().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].acc_lo = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify_par().is_err());
        }
        {
            let mut witness = witness.clone();
            witness.bytecode[1].cnt = Some(0x1.into());
            let prover = test_bytecode_circuit(witness);
            assert!(prover.verify_par().is_err());
        }
    }

    #[test]
    #[ignore]
    fn print_gates_lookups() {
        let gates = CircuitGates::collect::<Fr, BytecodeTestCircuit<Fr>>();
        let str = gates.queries_to_csv();
        for line in str.lines() {
            let last_csv = line.rsplitn(2, ',').next().unwrap();
            println!("{}", last_csv);
        }
    }
}
