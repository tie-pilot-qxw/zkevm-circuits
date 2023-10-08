use crate::constant::ADDRESS_HI_FOR_CREATE;
use crate::witness::Witness;
use eth_types::geth_types::{Account, GethData};
use eth_types::{Address, Block, Field, Transaction, U256};
pub use gadgets::util::Expr;
use halo2_proofs::circuit::{Cell, Layouter, Region, Value};
use halo2_proofs::plonk::{
    Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells,
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

/// Generate the code address for create-contract transaction of index `idx`
pub fn create_contract_temp_addr(idx: usize) -> U256 {
    let hi: U256 = ADDRESS_HI_FOR_CREATE.into();
    let lo: U256 = idx.into();
    (hi << 128) + lo
}

pub fn geth_data_test(bytecode: &[u8], input: &[u8], is_create: bool) -> GethData {
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
    let eth_block = Block {
        author: Some(Default::default()),
        number: Some(1.into()),
        base_fee_per_gas: Some(20000.into()),
        transactions: vec![tx],
        ..Default::default()
    };
    let account_addr = if is_create {
        create_contract_temp_addr(1)
    } else {
        to.as_bytes().into()
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
        accounts: vec![account],
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
    use crate::util::convert_u256_to_64_bytes;
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
}
