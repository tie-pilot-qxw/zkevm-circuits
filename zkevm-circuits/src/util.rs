use crate::constant::CREATE_ADDRESS_PREFIX;
use crate::witness::Witness;
use eth_types::geth_types::{Account, GethData};
use eth_types::{Address, Block, Field, GethExecTrace, ReceiptLog, Transaction, U256};
pub use gadgets::util::Expr;
use halo2_proofs::circuit::{Cell, Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells,
};
use std::io::Read;
use std::path::Path;
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
    ) -> Result<Self::Cells, Error>;

    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows() -> (usize, usize);

    /// Return the number of rows required to prove the witness.
    /// Only include the rows in witness and necessary padding, do not include padding to 2^k.
    fn num_rows(witness: &Witness) -> usize;
}

/// Ceiling of log_2(n)
pub fn log2_ceil(n: usize) -> u32 {
    u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
}

pub fn assign_advice_or_fixed<F: Field, C: Into<Column<Any>>>(
    region: &mut Region<'_, F>,
    offset: usize,
    value: &U256,
    column: C,
) -> Result<Cell, Error> {
    let column_any = column.into();
    let assigned_cell = match column_any.column_type() {
        Any::Advice(_) => region.assign_advice(
            || {
                format!(
                    "Column {:?} at offset={}, value={} ",
                    column_any, offset, value
                )
            },
            Column::<Advice>::try_from(column_any)
                .expect("should convert to Advice column successfully"),
            offset,
            || Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&value))),
        )?,
        Any::Fixed => region.assign_fixed(
            || {
                format!(
                    "Column {:?} at offset={}, value={} ",
                    column_any, offset, value
                )
            },
            Column::<Fixed>::try_from(column_any)
                .expect("should convert to Fixed column successfully"),
            offset,
            || Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(&value))),
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
pub fn create_contract_addr_with_prefix(tx: &Transaction) -> U256 {
    let prefix: U256 = CREATE_ADDRESS_PREFIX.into();
    let created_addr = create_contract_addr(tx);
    prefix + created_addr
}

pub fn geth_data_test(
    trace: GethExecTrace,
    bytecode: &[u8],
    input: &[u8],
    is_create: bool,
    receipt_log: ReceiptLog,
) -> GethData {
    let mut history_hashes = vec![];
    for i in 0..256 {
        history_hashes.push(i.into())
    }
    let mut tx = Transaction::default();
    let to: Address = [0xaa; 20].into();
    if !is_create {
        tx.input = input.to_vec().into();
        tx.to = Some(to);
    }
    let account_addr = if is_create {
        create_contract_addr_with_prefix(&tx)
    } else {
        to.as_bytes().into()
    };
    let eth_block = Block {
        author: Some(Default::default()),
        number: Some(1.into()),
        base_fee_per_gas: Some(20000.into()),
        transactions: vec![tx],
        ..Default::default()
    };
    let account = Account {
        address: account_addr,
        code: bytecode.to_vec().into(),
        ..Default::default()
    };
    GethData {
        chain_id: 42.into(),
        history_hashes,
        eth_block,
        geth_traces: vec![trace],
        accounts: vec![account],
        logs: vec![receipt_log],
    }
}

pub fn get_geth_data<P: AsRef<Path>>(
    block_info_file: P,
    tx_info_file: P,
    trace_file: P,
    receipt_file: P,
    accounts_file: P,
) -> GethData {
    let eth_block = read_block_from_api_result_file(block_info_file);
    let tx = read_tx_from_api_result_file(tx_info_file);
    // debug transaction trace
    let trace = read_trace_from_api_result_file(trace_file);
    // transaction receipt for public log
    let receipt_log = read_log_from_api_result_file(receipt_file);
    // make accounts
    let accounts = match tx.to {
        None => vec![Account {
            address: create_contract_addr_with_prefix(&tx),
            code: tx.input,
            ..Default::default()
        }],
        Some(_addr) => read_accounts_from_api_result_file(accounts_file),
    };

    let chain_id = tx.chain_id.unwrap();

    // make fake history hashes
    // TODO read hashes from file
    let mut history_hashes = vec![];
    for i in 0..256 {
        history_hashes.push(i.into())
    }

    // build and return geth_data
    GethData {
        chain_id: chain_id.into(),
        history_hashes,
        eth_block,
        accounts,
        geth_traces: vec![trace],
        logs: vec![receipt_log],
    }
}

/// A place to hold one of two outcomes:
/// Delta: current cell increases from previous cell by this expression
/// To: current cell becomes this expression
pub enum ExpressionOutcome<F> {
    Delta(Expression<F>),
    To(Expression<F>),
}

impl<F: Field> ExpressionOutcome<F> {
    pub(crate) fn into_constraint(
        self,
        minuend: Expression<F>,
        subtrahend: Expression<F>,
    ) -> Expression<F> {
        match self {
            ExpressionOutcome::Delta(delta) => minuend - subtrahend - delta,
            ExpressionOutcome::To(to) => minuend - to,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::util::{
        convert_f_to_u256, convert_u256_to_64_bytes, convert_u256_to_f, uint64_with_overflow,
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
}
