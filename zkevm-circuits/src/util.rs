use crate::witness;
use eth_types::Field;
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

    /// Create a new SubCircuit from a witness Block
    fn new_from_block(block: &witness::Block<F>) -> Self;

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
        // challenges: &Challenges<Value<F>>, todo challenges not defined yet
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Return the minimum number of rows required to prove the block.
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(/*block: &witness::Block<F> todo block not defined yet*/) -> (usize, usize);
}

#[macro_export]
macro_rules! add_expression_to_constraints {
    ($v:expr,$e:expr) => {
        $v.into_iter()
            .map(move |(name, constraint)| (name, $e * constraint))
    };
}

pub fn assign_row<F: Field>(
    region: &mut Region<'_, F>,
    offset: usize,
    witness: Vec<Option<u64>>,
    columns: Vec<Column<Any>>,
) -> Result<(), Error> {
    if columns.len() != witness.len() {
        return Err(Error::Synthesis);
    }
    for (idx, value) in witness.into_iter().enumerate() {
        if let Some(x) = value {
            match columns[idx].column_type() {
                Any::Advice(_) => {
                    region.assign_advice(
                        || {
                            format!(
                                "Column {:?} at offset={}, value={} ",
                                columns[idx], offset, x
                            )
                        },
                        Column::<Advice>::try_from(columns[idx]).unwrap(),
                        offset,
                        || Value::known(F::from(x as u64)),
                    )?;
                }
                Any::Fixed => {
                    region.assign_fixed(
                        || {
                            format!(
                                "Column {:?} at offset={}, value={} ",
                                columns[idx], offset, x
                            )
                        },
                        Column::<Fixed>::try_from(columns[idx]).unwrap(),
                        offset,
                        || Value::known(F::from(x as u64)),
                    )?;
                }
                Any::Instance => {
                    todo!()
                }
            }
        }
    }
    Ok(())
}
