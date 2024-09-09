// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::CREATE_ADDRESS_PREFIX;
use crate::witness::Witness;
use eth_types::call_types::GethCallTrace;
use eth_types::evm_types::{Memory, OpcodeId};
use eth_types::geth_types::{Account, ChunkData, GethData};
use eth_types::{Address, Block, Field, GethExecTrace, ReceiptLog, Transaction, U256};
use eth_types::{ToAddress, H256};
pub use gadgets::util::Expr;
use halo2_proofs::circuit::{Cell, Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Any, Challenge, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
    SecondPhase, VirtualCells,
};
use std::path::Path;
use std::str::FromStr;
use trace_parser::{
    read_accounts_from_api_result_file, read_block_from_api_result_file,
    read_log_from_api_result_file, read_trace_from_api_result_file, read_tx_from_api_result_file,
};

pub(crate) fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// Challenges
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    // randomness used for rlc in state circuit
    state_input: T,
    evm_word: T,
    keccak_input: T,
}

impl Challenges {
    /// Construct Challenges by allocating challenges in phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(test)]
        let _dummy = meta.advice_column_in(SecondPhase);
        Self {
            state_input: meta.challenge_usable_after(FirstPhase),
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
        }
    }
    /// Return expression of challenges from ConstraintSystem
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        Challenges {
            state_input: query_expression(meta, |meta| meta.query_challenge(self.state_input)),
            evm_word: query_expression(meta, |meta| meta.query_challenge(self.evm_word)),
            keccak_input: query_expression(meta, |meta| meta.query_challenge(self.keccak_input)),
        }
    }
    /// Return value of challenges from layouter
    pub fn values<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            state_input: layouter.get_challenge(self.state_input),
            evm_word: layouter.get_challenge(self.evm_word),
            keccak_input: layouter.get_challenge(self.keccak_input),
        }
    }

    pub fn mock_expr<F: Field>(
        state_input: Expression<F>,
        evm_word: Expression<F>,
        keccak_input: Expression<F>,
    ) -> Challenges<Expression<F>> {
        Challenges {
            state_input,
            evm_word,
            keccak_input,
        }
    }
}
impl<T: Clone> Challenges<T> {
    /// Return challenge of state_input
    pub fn state_input(&self) -> T {
        self.state_input.clone()
    }
    /// Returns challenge of `evm_word`.
    pub fn evm_word(&self) -> T {
        self.evm_word.clone()
    }

    /// Returns challenge of `keccak_input`.
    pub fn keccak_input(&self) -> T {
        self.keccak_input.clone()
    }
    /// Return the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [&self.state_input, &self.evm_word, &self.keccak_input]
    }

    pub(crate) fn mock(state_input: T, evm_word: T, keccak_input: T) -> Self {
        Self {
            state_input,
            evm_word,
            keccak_input,
        }
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }
    /// Return power series
    pub fn rlc_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.state_input.clone())
    }
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full Ethereum block verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Cells that need to use permutation constraints.
    type Cells;

    /// Create a new SubCircuit from witness
    fn new_from_witness(witness: &Witness) -> Self;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }

    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to. Return the cells that need to use permutation constraints.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Self::Cells, Error>;

    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows() -> (usize, usize);

    /// Return the number of rows required to prove the witness.
    /// Only include the rows in witness and necessary padding, do not include padding to 2^k.
    fn num_rows(witness: &Witness) -> usize;
}

/// Ceiling of log_2(n)
/// `log2_ceil(0)` returns 0.
pub fn log2_ceil(n: usize) -> u32 {
    (u32::BITS - (n as u32).leading_zeros()) - u32::from(n.is_power_of_two())
}

pub fn assign_advice_or_fixed_with_u256<F: Field, C: Into<Column<Any>>>(
    region: &mut Region<'_, F>,
    offset: usize,
    value: &U256,
    column: C,
) -> Result<Cell, Error> {
    let cell = assign_advice_or_fixed_with_value(
        region,
        offset,
        Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&value))),
        column,
    )?;
    Ok(cell)
}

pub fn assign_advice_or_fixed_with_value<F: Field, C: Into<Column<Any>>>(
    region: &mut Region<'_, F>,
    offset: usize,
    value: Value<F>,
    column: C,
) -> Result<Cell, Error> {
    let column_any = column.into();
    let assigned_cell = match column_any.column_type() {
        Any::Advice(_) => region.assign_advice(
            || {
                format!(
                    "Column {:?} at offset={}, value={:?} ",
                    column_any, offset, value
                )
            },
            Column::<Advice>::try_from(column_any)
                .expect("should convert to Advice column successfully"),
            offset,
            || value,
        )?,
        Any::Fixed => region.assign_fixed(
            || {
                format!(
                    "Column {:?} at offset={}, value:{:?}",
                    column_any, offset, value
                )
            },
            Column::<Fixed>::try_from(column_any)
                .expect("should convert to Fixed column successfully"),
            offset,
            || value,
        )?,
        _ => {
            panic!("should not call this on Instance column")
        }
    };
    Ok(assigned_cell.cell())
}
pub fn convert_u256_to_64_bytes(value: &U256) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    value.to_little_endian(&mut bytes[..32]);
    bytes
}

pub fn convert_u256_to_be_bytes(value: &U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes[..32]);
    bytes
}

pub fn convert_f_to_u256<F: Field>(value: &F) -> U256 {
    U256::from_little_endian(&value.to_repr())
}

pub fn convert_u256_to_f<F: Field>(value: &U256) -> F {
    F::from_uniform_bytes(&convert_u256_to_64_bytes(value))
}

pub fn uint64_with_overflow(value: &U256) -> bool {
    value.leading_zeros() < 3 * 8 * 8
}

/// Generate the code address for create-contract transaction
pub fn create_contract_addr(tx: &Transaction) -> U256 {
    if tx.to.is_some() {
        panic!("should not use tx with `tx.to` non-empty");
    }
    let mut stream = ethers_core::utils::rlp::RlpStream::new();
    stream.begin_list(2);
    stream.append(&tx.from);
    stream.append(&tx.nonce.as_u64());
    let result = stream.out().to_vec();
    let hash = ethers_core::utils::keccak256(result);
    (&hash[12..]).into()
}

/// Generate the code address for create-contract transaction with prefix 0xff...ff
/// Note: There are two types of contract bytecode: original Bytecode, deployed Bytecode,
///       The Bytecode used by the exchange that creates the contract is the original Bytecode, and the
///     Bytecode used by the exchange that calls the contract is the deployed Bytecode.
///       In order to distinguish these two Bytecodes in the circuit, for the Bytecode address used to
///    create the contract transaction, use the following rules: 0xfffff...(12 f) + transactionIdex
pub fn create_contract_addr_with_prefix(tx: &Transaction) -> U256 {
    let prefix: U256 = CREATE_ADDRESS_PREFIX.into();
    prefix + tx.transaction_index.unwrap().as_usize()
}

// cal memory usage for each step
pub fn preprocess_trace(trace: &mut GethExecTrace) {
    let last_mem = trace
        .struct_logs
        .last()
        .map(|v| v.memory.clone())
        .unwrap_or_default();
    let mut mem: Vec<Memory> = trace
        .struct_logs
        .iter()
        .map(|step| step.memory.clone())
        .chain(std::iter::once(last_mem))
        .collect();
    mem.remove(0);

    for (i, step) in trace.struct_logs.iter_mut().enumerate() {
        let mut mem_tmp = if i == 0 {
            Memory::default()
        } else {
            mem[i - 1].clone()
        };

        step.memory = match step.op {
            OpcodeId::RETURN => {
                //calculate the correct mem usage of return
                let dst_offset = step.stack.last().unwrap();
                let length = step.stack.nth_last(1).unwrap();
                mem_tmp.extend_at_least((dst_offset + length).as_usize());
                mem_tmp
            }
            OpcodeId::STOP => {
                // calculate the correct mem usage of stop
                mem_tmp
            }
            OpcodeId::CALL => {
                // calculate the correct mem usage of call
                let args_offset = step.stack.nth_last(3).unwrap();
                let args_size = step.stack.nth_last(4).unwrap();
                let ret_offset = step.stack.nth_last(5).unwrap();
                let ret_size = step.stack.nth_last(6).unwrap();

                mem_tmp.extend_at_least((ret_offset + ret_size).as_usize());
                mem_tmp.extend_at_least((args_offset + args_size).as_usize());
                mem_tmp
            }

            _ => mem[i].clone(),
        };
    }
    if trace.call_trace.is_empty() {
        trace.call_trace = GethCallTrace::get_call_trace_for_test(&trace.struct_logs);
    }
}

pub fn chunk_data_test(
    trace: GethExecTrace,
    bytecode: &[u8],
    input: &[u8],
    is_create: bool,
    receipt_log: ReceiptLog,
) -> ChunkData {
    let mut history_hashes = vec![];
    #[cfg(not(feature = "no_block_hash"))]
    for i in 0..=256 {
        history_hashes.push(i.into())
    }
    let mut tx = Transaction::default();
    let to = Address::from_str("0x0000000000000000000000007265636569766572").unwrap_or_default();
    if !is_create {
        tx.input = input.to_vec().into();
        tx.to = Some(to);
    }
    tx.gas = U256::from_str("0x2540be400").unwrap_or_default();
    tx.from = Address::from_str("0x000000000000000000000000000073656e646572").unwrap_or_default();
    let account_addr = if is_create {
        create_contract_addr_with_prefix(&tx)
    } else {
        to.as_bytes().into()
    };
    let eth_block = Block {
        author: Some(Default::default()),
        number: Some(0.into()),
        base_fee_per_gas: Some(1000000000.into()),
        gas_limit: U256::from_str("0x2540b91f8").unwrap_or_default(),
        transactions: vec![tx],
        mix_hash: Some(H256::zero()), // evm without prevstate default to zero
        ..Default::default()
    };
    let account = Account {
        address: account_addr,
        code: bytecode.to_vec().into(),
        ..Default::default()
    };

    let mut trace_new = trace.clone();
    preprocess_trace(&mut trace_new);

    ChunkData {
        chain_id: 1337.into(),
        history_hashes,
        blocks: vec![GethData {
            eth_block,
            geth_traces: vec![trace_new],
            accounts: vec![account],
            logs: vec![receipt_log],
        }],
    }
}

pub fn get_chunk_data<P: AsRef<Path>>(
    block_info_file: P,
    tx_info_file: P,
    trace_file: P,
    receipt_file: P,
    accounts_file: P,
) -> ChunkData {
    let eth_block = read_block_from_api_result_file(block_info_file);
    let tx = read_tx_from_api_result_file(tx_info_file);
    // debug transaction trace and preprocess trace
    let mut trace = read_trace_from_api_result_file(trace_file);
    preprocess_trace(&mut trace);

    // transaction receipt for public log
    let mut receipt_log = read_log_from_api_result_file(receipt_file);

    // make accounts
    let accounts = match tx.to {
        None => {
            let contract_addr = create_contract_addr_with_prefix(&tx);
            // modify log.address
            for log in receipt_log.logs.iter_mut() {
                log.address = contract_addr.to_address();
            }
            vec![Account {
                address: contract_addr,
                code: tx.input,
                ..Default::default()
            }]
        }
        Some(_addr) => read_accounts_from_api_result_file(accounts_file),
    };
    let chain_id = tx.chain_id.unwrap();

    // make fake history hashes
    // TODO read hashes from file
    let mut history_hashes = vec![];
    for i in 0..=256 {
        history_hashes.push(i.into())
    }

    // build and return chunk_data
    ChunkData {
        chain_id: chain_id.into(),
        history_hashes,
        blocks: vec![GethData {
            eth_block,
            accounts,
            geth_traces: vec![trace],
            logs: vec![receipt_log],
        }],
    }
}

pub fn get_multi_trace_chunk_data<P: AsRef<Path>>(
    block_info_file: P,
    tx_info_files: Vec<&str>,
    trace_files: Vec<&str>,
    receipt_files: Vec<&str>,
    accounts_file: P,
) -> ChunkData {
    let eth_block = read_block_from_api_result_file(block_info_file);

    // debug transaction trace
    let mut geth_traces: Vec<GethExecTrace> = vec![];
    for trace_file in trace_files.iter() {
        let mut trace = read_trace_from_api_result_file(trace_file);
        preprocess_trace(&mut trace);
        geth_traces.push(trace)
    }

    // transaction receipt for public log
    let mut logs: Vec<ReceiptLog> = vec![];
    for receipt_file in receipt_files.iter() {
        let receipt_log = read_log_from_api_result_file(receipt_file);
        logs.push(receipt_log)
    }

    // make accounts
    let mut accounts: Vec<Account> = vec![];
    let mut chain_id: U256 = U256::zero();
    accounts.append(&mut read_accounts_from_api_result_file(accounts_file));

    for tx_info_file in tx_info_files.iter() {
        let tx = read_tx_from_api_result_file(tx_info_file);
        if chain_id == U256::zero() {
            chain_id = tx.chain_id.unwrap();
        }
        if tx.to == None {
            let account = Account {
                address: create_contract_addr_with_prefix(&tx),
                code: tx.input,
                ..Default::default()
            };
            accounts.push(account)
        }
    }

    // make fake history hashes
    // TODO read hashes from file
    let mut history_hashes = vec![];
    for i in 0..=256 {
        history_hashes.push(i.into())
    }

    // build and return chunk_data
    ChunkData {
        chain_id: chain_id.into(),
        history_hashes,
        blocks: vec![GethData {
            eth_block,
            accounts,
            geth_traces,
            logs,
        }],
    }
}

/// A place to hold one of two outcomes:
/// Delta: current cell increases from previous cell by this expression
/// To: current cell becomes this expression
#[derive(Clone)]
pub enum ExpressionOutcome<F> {
    Delta(Expression<F>),
    To(Expression<F>),
    Any,
}

impl<F: Field> ExpressionOutcome<F> {
    pub(crate) fn into_constraint(
        self,
        minuend: Expression<F>,
        subtrahend: Expression<F>,
    ) -> Option<Expression<F>> {
        match self {
            ExpressionOutcome::Delta(delta) => Some(minuend - subtrahend - delta),
            ExpressionOutcome::To(to) => Some(minuend - to),
            ExpressionOutcome::Any => None,
        }
    }
}

/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub mod rlc {
    use std::ops::{Add, Mul};

    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
        if !expressions.is_empty() {
            generic(expressions.iter().map(|e| e.expr()), randomness.expr())
        } else {
            0.expr()
        }
    }

    pub(crate) fn value<'a, F: Field, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| F::from(*v as u64))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::ZERO
        }
    }

    fn generic<V, I>(values: I, randomness: V) -> V
    where
        I: IntoIterator<Item = V>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
        V: Clone + Add<Output = V> + Mul<Output = V>,
    {
        let mut values = values.into_iter().rev();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
    }
}

pub(crate) trait ConstrainBuilderCommon<F: Field> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>);

    fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.add_constraint(name, constraint);
    }

    fn require_equal(&mut self, name: &'static str, lhs: Expression<F>, rhs: Expression<F>) {
        self.add_constraint(name, lhs - rhs);
    }

    fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name,
            set.iter()
                .fold(1.expr(), |acc, item| acc * (value.clone() - item.clone())),
        );
    }

    fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }
}

#[derive(Default)]
pub struct BaseConstraintBuilder<F> {
    pub constraints: Vec<(&'static str, Expression<F>)>,
    pub max_degree: usize,
    pub condition: Option<Expression<F>>,
}

impl<F: Field> ConstrainBuilderCommon<F> for BaseConstraintBuilder<F> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree(), name);
        self.constraints.push((name, constraint));
    }
}

impl<F: Field> BaseConstraintBuilder<F> {
    pub(crate) fn new(max_degree: usize) -> Self {
        BaseConstraintBuilder {
            constraints: Vec::new(),
            max_degree,
            condition: None,
        }
    }

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret: R = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }

    pub(crate) fn gate(&self, selector: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .clone()
            .into_iter()
            .map(|(name, constraint)| (name, selector.clone() * constraint))
            .filter(|(name, constraint)| {
                self.validate_degree(constraint.degree(), name);
                true
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::util::{
        convert_f_to_u256, convert_u256_to_64_bytes, convert_u256_to_be_bytes, convert_u256_to_f,
        uint64_with_overflow,
    };
    use eth_types::U256;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::ff::FromUniformBytes;
    use std::str::FromStr;

    #[test]
    fn test_convert() {
        let input_1: U256 = U256::from(1);
        assert_eq!(
            convert_u256_to_64_bytes(&input_1),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let input_16: U256 = U256::from_str("f").unwrap();
        assert_eq!(
            convert_u256_to_64_bytes(&input_16),
            [
                15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let input_max: U256 =
            U256::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert_eq!(
            convert_u256_to_64_bytes(&input_max),
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0
            ]
        );
    }

    #[test]
    fn test_convert_fr() {
        let input_1 = U256::from(1);
        let field_1 = Fr::one();
        assert_eq!(
            Fr::from_uniform_bytes(&convert_u256_to_64_bytes(&input_1)),
            field_1
        );
    }
    #[test]
    fn test_overflow() {
        let x: [u8; 32] = [
            255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let input_overflow = U256::from_little_endian(&x);
        assert_eq!(uint64_with_overflow(&input_overflow), true);
        let x: [u8; 32] = [
            255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0,
        ];
        let input_overflow = U256::from_little_endian(&x);
        assert_eq!(uint64_with_overflow(&input_overflow), true);
        let x: [u8; 32] = [
            255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let input_no_overflow = U256::from_little_endian(&x);
        assert_eq!(uint64_with_overflow(&input_no_overflow), false);
    }

    #[test]
    fn test_convert_u256_f() {
        let input_0 = U256::from(0);
        let field_0 = Fr::zero();
        assert_eq!(input_0, convert_f_to_u256(&field_0));

        let input_1 = U256::from(1);
        let field_1 = Fr::one();
        assert_eq!(input_1, convert_f_to_u256(&field_1));

        //let input_max = U256::MAX;

        let x: [u8; 32] = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 47,
        ];
        let v = U256::from_little_endian(&x);
        let field_max = convert_u256_to_f::<Fr>(&v);
        assert_eq!(v, convert_f_to_u256(&field_max));
    }

    #[test]
    fn test_convert_u256_to_be_bytes() {
        let input_1: U256 = U256::from(1);
        assert_eq!(
            convert_u256_to_be_bytes(&input_1),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
        );

        let input_15: U256 = U256::from_str("f").unwrap();
        assert_eq!(
            convert_u256_to_be_bytes(&input_15),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 15
            ]
        );
        let input: U256 =
            U256::from_str("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert_eq!(
            convert_u256_to_be_bytes(&input),
            [
                239, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
            ]
        );
    }
}
