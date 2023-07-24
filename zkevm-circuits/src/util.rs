use crate::witness::Witness;
use eth_types::{Field, U256};
pub use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Any, Column, ConstraintSystem, Error, Fixed};

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

    /// Create a new SubCircuit from witness
    fn new_from_witness(witness: &Witness) -> Self;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }

    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows() -> (usize, usize);

    /// Return the number of rows required to prove the witness.
    /// Only include the rows in witness and necessary padding, do not include padding to 2^k.
    fn num_rows(witness: &Witness) -> usize;
}

#[macro_export]
macro_rules! add_expression_to_constraints {
    ($v:expr,$e:expr) => {
        $v.into_iter()
            .map(move |(name, constraint)| (name, $e * constraint))
    };
}

pub fn assign_advice_or_fixed<F: Field, C: Into<Column<Any>>>(
    region: &mut Region<'_, F>,
    offset: usize,
    value: &U256,
    column: C,
) -> Result<(), Error> {
    let column_any = column.into();
    match column_any.column_type() {
        Any::Advice(_) => {
            region.assign_advice(
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
            )?;
        }
        Any::Fixed => {
            region.assign_fixed(
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
            )?;
        }
        _ => {
            panic!("should not call this on Instance column")
        }
    }
    Ok(())
}

pub fn convert_u256_to_64_bytes(value: &U256) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    value.to_little_endian(&mut bytes[..32]);
    bytes
}

#[cfg(test)]
mod tests {
    use crate::util::convert_u256_to_64_bytes;
    use eth_types::{Field, U256};
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
