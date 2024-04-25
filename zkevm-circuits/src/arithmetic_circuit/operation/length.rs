use crate::arithmetic_circuit::operation::{
    get_lt_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};

use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::util::Expr;

use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct LengthGadget<F>(PhantomData<F>);

/// The length algorithm is mainly used to determine
/// whether the length of the code to be copied is correct when copying data.
/// Length circuit function:
//    Inputs: offset, length, size
//    Returns: real_len, zero_len, overflow, real_len_is_zero, zero_len_is_zero
//     Determine if offset + length > size
//     Three cases (regardless of whether length is 0), need to return (real_len, zero_len):
//        a. If offset + length <= size, return (length, 0)
//        b. If offset + length > size, there are two sub-cases:
//            i. If offset < size, return (size - offset, offset + length - size)
//            ii. If offset >= size, return (0, length)
//  The offset, length, size and offset + length, all need u64_overflow constraint.
impl<F: Field> OperationGadget<F> for LengthGadget<F> {
    // arithmetic name
    fn name(&self) -> &'static str {
        "LENGTH"
    }
    // arithmetic tag
    fn tag(&self) -> Tag {
        Tag::Length
    }

    // arithmetic num_row
    fn num_row(&self) -> usize {
        3
    }

    // arithmetic unusable_rows
    fn unusable_rows(&self) -> (usize, usize) {
        (3, 1)
    }

    // arithmetic constrains
    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // get operations
        let [offset, length] = config.get_operand(0)(meta);
        let [size, overflow] = config.get_operand(1)(meta);
        let [real_len, zero_len] = config.get_operand(2)(meta);
        let [real_len_is_zero, zero_len_is_zero] = config.get_operand(3)(meta);
        let [real_len_inv, zero_len_inv] = config.get_operand(4)(meta);
        let [lt_offset_size, _] = config.get_operand(5)(meta);

        // get u16s
        let (_, offset_u16s, length_u16s) = get_u16s(config, meta, Rotation::cur());
        let (_, size_u16s, offset_bound_u16s) = get_u16s(config, meta, Rotation::prev());
        let (_, diff_u16s, diff_offset_size_u16s) = get_u16s(config, meta, Rotation(-2));

        let mut constraints = vec![];

        // constraint operation value from u16s
        constraints.extend([
            (
                "constraint offset".into(),
                offset.clone() - offset_u16s.clone(),
            ),
            (
                "constraint length".into(),
                length.clone() - length_u16s.clone(),
            ),
            ("constraint size".into(), size.clone() - size_u16s.clone()),
            (
                "constraint offset_bound".into(),
                offset.clone() + length.clone() - offset_bound_u16s.clone(),
            ),
        ]);

        // constraint overflow must be 0 or 1
        constraints.push((
            "overflow must be 0 or 1".to_string(),
            overflow.clone() * (overflow.clone() - 1.expr()),
        ));
        // Constraint the size relationship between size and offset_bound
        let is_overflow: SimpleLtGadget<F, 8> =
            SimpleLtGadget::new(&size, &offset_bound_u16s, &overflow, &diff_u16s);
        constraints.extend(is_overflow.get_constraints());

        // constraint lt_offset_size must be 0 or 1
        constraints.push((
            "lt_offset_size must be 0 or 1".to_string(),
            lt_offset_size.clone() * (lt_offset_size.clone() - 1.expr()),
        ));
        // Constrain the size relationship between offset and size
        let is_lt_offset_size: SimpleLtGadget<F, 8> =
            SimpleLtGadget::new(&offset, &size, &lt_offset_size, &diff_offset_size_u16s);
        constraints.extend(is_lt_offset_size.get_constraints());

        // constraint real_len
        constraints.push((
            "real_len = (1-overflow) * length + overflow *  lt_offset_size * (size - offset)"
                .into(),
            (1.expr() - overflow.clone()) * length.clone()
                + overflow.clone() * lt_offset_size.clone() * (size.clone() - offset.clone())
                - real_len.clone(),
        ));
        // constraint zero_len
        constraints.push((
            "zero_len = overflow * lt_offset_size * (offset_bound - size) + overflow * (1 - lt_offset_size) * length"
                .into(),
            overflow.clone() * lt_offset_size.clone() * (offset_bound_u16s.clone() - size.clone())
            + overflow.clone() * (1.expr() - lt_offset_size.clone()) * length.clone()
                - zero_len.clone(),
        ));

        // constraint real_len_is_zero and zero_len_is_zero
        let real_len_gadget = SimpleIsZero::new(&real_len, &real_len_inv, String::from("real_len"));
        let zero_len_gadget = SimpleIsZero::new(&zero_len, &zero_len_inv, String::from("zero_len"));
        constraints.extend(real_len_gadget.get_constraints());
        constraints.extend(zero_len_gadget.get_constraints());
        constraints.extend([
            (
                "real_len_is_zero = real_len_gadget.expr()".into(),
                real_len_is_zero.clone() - real_len_gadget.expr(),
            ),
            (
                "zero_len_is_zero = zero_len_gadget.expr()".into(),
                zero_len_is_zero.clone() - zero_len_gadget.expr(),
            ),
        ]);

        constraints
    }
}

/// Generate the witness and return operation result
/// +--------------+--------------+------------------+------------------+-----+-----------+------------------+
/// | operand0     | operand1     | operand2         | operand3         | cnt | u16s(0-3) | u16s(4_7)        |
/// +--------------+--------------+------------------+------------------+-----+-----------+------------------+
/// | real_len_inv | zero_len_inv | lt_offset_size   |                  | 2   | diff      | diff_offset_size |
/// | real_len     | zero_len     | real_len_is_zero | zero_len_is_zero | 1   | size      | offset_bound     |
/// | offset       | length       | size             | overflow         | 0   | offset    | length           |
/// +--------------+--------------+------------------+------------------+-----+-----------+------------------+
/// It is called during core circuit's gen_witness
/// Input ([offset, length, size])
/// Output ([row_2, row_1, row_0], [overflow, real_len, zero_len])
/// The three input parameters above and (offset + length) must be in the range of u64.
pub(crate) fn gen_witness<F: Field>(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    // Assert that the number of operands is 3
    assert_eq!(3, operands.len());

    // Get the three operands, and panic if the three operands or (offset + length) are not in the range of u64.
    let offset = operands[0].as_u64();
    let length = operands[1].as_u64();
    let size = operands[2].as_u64();
    let offset_bound = offset
        .checked_add(length)
        .expect("offset + length overflow");

    let length_inv = U256::from_little_endian(
        F::from(length)
            .invert()
            .unwrap_or(F::ZERO)
            .to_repr()
            .as_ref(),
    );

    // Calculate real_len, zero_len and their inverse values.
    let (real_len, real_len_inv, zero_len, zero_len_inv) = if offset + length <= size {
        (length.into(), length_inv, U256::zero(), U256::zero())
    } else if offset < size {
        (
            (size - offset).into(),
            U256::from_little_endian(
                F::from(size - offset)
                    .invert()
                    .unwrap_or(F::ZERO)
                    .to_repr()
                    .as_ref(),
            ),
            (offset + length - size).into(),
            U256::from_little_endian(
                F::from(offset + length - size)
                    .invert()
                    .unwrap_or(F::ZERO)
                    .to_repr()
                    .as_ref(),
            ),
        )
    } else {
        (U256::zero(), U256::zero(), length.into(), length_inv)
    };

    let mut offset_u16s: Vec<u16> = offset
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let length_u16s: Vec<u16> = length
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let offset_bound_u16s: Vec<u16> = offset_bound
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let mut size_u16s: Vec<u16> = size
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();

    let (overflow, _, mut diff_u16s) = get_lt_operations(
        &size.into(),
        &offset_bound.into(),
        &U256::from(2).pow(U256::from(64)),
    );

    let (lt_offset_size, _, mut diff_offset_size_u16s) = get_lt_operations(
        &offset.into(),
        &size.into(),
        &U256::from(2).pow(U256::from(64)),
    );

    offset_u16s.extend(length_u16s);
    let row_0 = get_row(
        [offset.into(), length.into()],
        [size.into(), U256::from(overflow as u8)],
        offset_u16s,
        0,
        Tag::Length,
    );

    size_u16s.extend(offset_bound_u16s);
    let row_1 = get_row(
        [real_len, zero_len],
        [
            U256::from(real_len.is_zero() as u8),
            U256::from(zero_len.is_zero() as u8),
        ],
        size_u16s,
        1,
        Tag::Length,
    );

    let _ = diff_u16s.split_off(4);
    let _ = diff_offset_size_u16s.split_off(4);
    diff_u16s.extend(diff_offset_size_u16s);

    let row_2 = get_row(
        [real_len_inv, zero_len_inv],
        [U256::from(lt_offset_size as u8), U256::zero()],
        diff_u16s,
        2,
        Tag::Length,
    );

    (
        vec![row_2, row_1, row_0],
        vec![U256::from(overflow as u8), real_len, zero_len],
    )
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(LengthGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use eth_types::U256;

    use super::gen_witness;
    use crate::witness::Witness;
    use halo2_proofs::halo2curves::bn256::Fr;

    // test offset + length < size
    #[test]
    fn test_gen_witness() {
        let offset = 32.into();
        let length = 100.into();
        let size = 256.into();

        let (arithmetic, result) = gen_witness::<Fr>(vec![offset, length, size]);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();
        assert_eq!(result[0], U256::zero());
    }

    // test offset + length > size && offset < size
    #[test]
    fn test_gen_witness_1() {
        let offset = 32.into();
        let length = 100.into();
        let size = 64.into();

        let (arithmetic, result) = gen_witness::<Fr>(vec![offset, length, size]);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();
        assert_eq!(result[0], U256::one());
    }

    // test offset + length > size && offset >= size
    #[test]
    fn test_gen_witness_2() {
        let offset = 32.into();
        let length = 100.into();
        let size = 32.into();

        let (arithmetic, result) = gen_witness::<Fr>(vec![offset, length, size]);

        let witness = Witness {
            arithmetic,
            ..Default::default()
        };
        witness.print_csv();
        assert_eq!(result[0], U256::one());
    }
}
