use crate::arithmetic_circuit::operation::{
    get_lt_word_operations, get_row, get_u16s, OperationConfig, OperationGadget,
};
use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256, U512};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::util::{pow_of_two, split_u256_hi_lo, split_u256_limb64, Expr};
use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct AddModGadget<F>(PhantomData<F>);

impl<F: Field> OperationGadget<F> for AddModGadget<F> {
    // Operation name
    fn name(&self) -> &'static str {
        "AddMod"
    }

    // Operation tag
    fn tag(&self) -> Tag {
        Tag::Addmod
    }

    // Number of rows required for AddMod operation
    fn num_row(&self) -> usize {
        12
    }

    // Unusable rows for AddMod operation
    fn unusable_rows(&self) -> (usize, usize) {
        (12, 1)
    }

    // Get constraints for AddMod operation
    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // get operations
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let n = config.get_operand(2)(meta);
        let r = config.get_operand(3)(meta);
        let rn_carry_lt = config.get_operand(4)(meta);
        let rn_diff = config.get_operand(5)(meta);
        let q = config.get_operand(6)(meta);
        let a_plus_b = config.get_operand(7)(meta);
        let [carry_0, carry_1] = config.get_operand(8)(meta);
        let [q_overflow, _] = config.get_operand(9)(meta);
        let [a_plus_b_lo_carry, a_plus_b_hi_carry] = config.get_operand(10)(meta);

        // get the u16s
        let (u16_sum_for_r_hi, _, _) = get_u16s(config, meta, Rotation::cur());
        let (u16_sum_for_r_lo, _, _) = get_u16s(config, meta, Rotation::prev());
        let (u16_sum_for_n_hi, n_hi_1, n_hi_2) = get_u16s(config, meta, Rotation(-2));
        let (u16_sum_for_n_lo, n_lo_1, n_lo_2) = get_u16s(config, meta, Rotation(-3));
        let (u16_sum_for_q_hi, q_hi_1, q_hi_2) = get_u16s(config, meta, Rotation(-4));
        let (u16_sum_for_q_lo, q_lo_1, q_lo_2) = get_u16s(config, meta, Rotation(-5));
        let (u16_sum_for_a_plus_b_hi, _, _) = get_u16s(config, meta, Rotation(-6));
        let (u16_sum_for_a_plus_b_lo, _, _) = get_u16s(config, meta, Rotation(-7));
        let (u16_sum_for_carry_0, _, _) = get_u16s(config, meta, Rotation(-8));
        let (u16_sum_for_carry_1, _, _) = get_u16s(config, meta, Rotation(-9));
        let (u16_sum_for_rn_diff_hi, _, _) = get_u16s(config, meta, Rotation(-10));
        let (u16_sum_for_rn_diff_lo, _, _) = get_u16s(config, meta, Rotation(-11));

        // get the u16 sum
        let u16_sum_for_r = [u16_sum_for_r_hi, u16_sum_for_r_lo];
        let u16_sum_for_n = [u16_sum_for_n_hi, u16_sum_for_n_lo];
        let u16_sum_for_q = [u16_sum_for_q_hi, u16_sum_for_q_lo];
        let u16_sum_for_a_plus_b = [u16_sum_for_a_plus_b_hi, u16_sum_for_a_plus_b_lo];
        let u16_sum_for_rn_diff = [u16_sum_for_rn_diff_hi, u16_sum_for_rn_diff_lo];

        let mut constraints: Vec<(String, Expression<F>)> = vec![];

        // Constrain the u16 sum and the value of the operand.
        for i in 0..2 {
            let hi_or_lo = if i == 0 { "hi" } else { "lo" };

            // Constraints for r
            constraints.push((
                format!("r_{} = u16 sum", hi_or_lo),
                r[i].clone() - u16_sum_for_r[i].clone(),
            ));

            // Constraints for n
            constraints.push((
                format!("n_{} = u16 sum", hi_or_lo),
                n[i].clone() - u16_sum_for_n[i].clone(),
            ));

            // Constraints for q
            constraints.push((
                format!("q_{} = u16 sum", hi_or_lo),
                q[i].clone() - u16_sum_for_q[i].clone(),
            ));

            // Constraints for a_plus_b
            constraints.push((
                format!("a_plus_b_{} = u16 sum", hi_or_lo),
                a_plus_b[i].clone() - u16_sum_for_a_plus_b[i].clone(),
            ));

            // Constraints for rn_diff
            constraints.push((
                format!("rn_diff_{} = u16 sum", hi_or_lo),
                rn_diff[i].clone() - u16_sum_for_rn_diff[i].clone(),
            ));
        }

        // Constrain carry_0
        constraints.push((
            "carry_0 = u16 sum".to_string(),
            carry_0.clone() - u16_sum_for_carry_0.clone(),
        ));

        // Constrain carry_1
        constraints.push((
            "carry_1 = u16 sum".to_string(),
            carry_1.clone() - u16_sum_for_carry_1.clone(),
        ));

        // Constrain a_plus_b_hi_carry and a_plus_b_lo_carry must be 0 or 1
        constraints.push((
            "a_plus_b_hi_carry must be 0 or 1".to_string(),
            a_plus_b_hi_carry.clone() * (a_plus_b_hi_carry.clone() - 1.expr()),
        ));

        constraints.push((
            "a_plus_b_lo_carry must be 0 or 1".to_string(),
            a_plus_b_lo_carry.clone() * (a_plus_b_lo_carry.clone() - 1.expr()),
        ));

        // Constrain q_overflow must be 0 or 1
        constraints.push((
            "q_overflow must be 0 or 1".to_string(),
            q_overflow.clone() * (q_overflow.clone() - 1.expr()),
        ));

        // Constrain when n != 0, r must less than n
        let r_lt_n_lo = SimpleLtGadget::new(&r[1], &n[1], &rn_carry_lt[1], &rn_diff[1]);
        let r_lt_n = SimpleLtWordGadget::new(&r[0], &n[0], &rn_carry_lt[0], &rn_diff[0], r_lt_n_lo);
        constraints.extend(r_lt_n.get_constraints());
        constraints.push((
            "r < n, when n != 0".to_string(),
            (1.expr() - r_lt_n.expr()) * (n[0].clone() + n[1].clone()),
        ));

        // Constrain n = 1 && a_plus_b_hi_carry = 1, when q_overflow = 1
        constraints.push((
            "n_lo = 1, when q_overflow = 1".to_string(),
            q_overflow.clone() * (1.expr() - n[1].clone()),
        ));
        constraints.push((
            "n_hi = 0, when q_overflow = 1".to_string(),
            q_overflow.clone() * n[0].clone(),
        ));
        constraints.push((
            "a_plus_b_hi_carry = 1, when q_overflow = 1".to_string(),
            q_overflow.clone() * (1.expr() - a_plus_b_hi_carry.clone()),
        ));

        // Constrain a + b = a_plus_b_hi_carry * 2^256 + a_plus_b
        constraints.push((
            "a_lo + b_lo = a_plus_b_lo + a_plus_b_lo_carry * 2^128".to_string(),
            a[1].clone() + b[1].clone()
                - a_plus_b[1].clone()
                - a_plus_b_lo_carry.clone() * pow_of_two::<F>(128),
        ));

        constraints.push((
            "a_hi + b_hi + a_plus_b_lo_carry = a_plus_b_hi + a_plus_b_hi_carry * 2^128".to_string(),
            a[0].clone() + b[0].clone() + a_plus_b_lo_carry.clone()
                - a_plus_b[0].clone()
                - (a_plus_b_hi_carry.clone() * pow_of_two::<F>(128)),
        ));

        // NOTE: When n = 0, r is equal to b;
        //       When n != 0, r is less than b.
        //       Therefore, the expression r_lt_n is equivalent to n = 0 expression.
        // When n = 0, n_is_zero = 1, otherwise n_is_zero = 0.
        let n_is_zero = r_lt_n.expr();

        // When n != 0, we should constrain
        // t0 + t1 * 2^64 + r_lo = a_plus_b_lo + carry_0 * 2^128
        // t2 + t3 * 2^64 + r_hi + carry_0 = a_plus_b_hi + carry_1 * 2^128
        // t4 + t5 * 2^64 + n_lo * q_overflow + carry_1 = a_plus_b_hi_carry
        // t6 + n_hi * q_overflow = 0
        let mut n_limbs = vec![];
        let mut q_limbs = vec![];
        n_limbs.extend([n_lo_1, n_lo_2, n_hi_1, n_hi_2]);
        q_limbs.extend([q_lo_1, q_lo_2, q_hi_1, q_hi_2]);

        let t0 = n_limbs[0].clone() * q_limbs[0].clone();
        let t1 = n_limbs[0].clone() * q_limbs[1].clone() + n_limbs[1].clone() * q_limbs[0].clone();
        let t2 = n_limbs[0].clone() * q_limbs[2].clone()
            + n_limbs[1].clone() * q_limbs[1].clone()
            + n_limbs[2].clone() * q_limbs[0].clone();
        let t3 = n_limbs[0].clone() * q_limbs[3].clone()
            + n_limbs[1].clone() * q_limbs[2].clone()
            + n_limbs[2].clone() * q_limbs[1].clone()
            + n_limbs[3].clone() * q_limbs[0].clone();
        let t4 = n_limbs[1].clone() * q_limbs[3].clone()
            + n_limbs[2].clone() * q_limbs[2].clone()
            + n_limbs[3].clone() * q_limbs[1].clone();
        let t5 = n_limbs[2].clone() * q_limbs[3].clone() + n_limbs[3].clone() * q_limbs[2].clone();
        let t6 = n_limbs[3].clone() * q_limbs[3].clone();

        // Constraint t0 + t1 * 2^64 + r_lo = a_plus_b_lo + carry_0 * 2^128, when n != 0.
        constraints.push((
            "t0 + t1 * 2^64 + r_lo = a_plus_b_lo + carry_0 * 2^128".to_string(),
            (1.expr() - n_is_zero.clone())
                * (t0.clone() + t1.clone() * pow_of_two::<F>(64) + r[1].clone()
                    - a_plus_b[1].clone()
                    - carry_0.clone() * pow_of_two::<F>(128)),
        ));

        // Constraint t2 + t3 * 2^64 + r_hi + carry_0 = a_plus_b_hi + carry_1 * 2^128, when n != 0.
        constraints.push((
            "t2 + t3 * 2^64 + r_hi + carry_0 = a_plus_b_hi + carry_1 * 2^128".to_string(),
            (1.expr() - n_is_zero.clone())
                * (t2.clone() + t3.clone() * pow_of_two::<F>(64) + r[0].clone() + carry_0.clone()
                    - a_plus_b[0].clone()
                    - carry_1.clone() * pow_of_two::<F>(128)),
        ));

        // Constraint t4 + t5 * 2^64 + n_lo * q_overflow + carry_1 = a_plus_b_hi_carry, when n != 0.
        constraints.push((
            "t4 + t5 * 2^64 + n_lo * q_overflow + carry_1 = a_plus_b_hi_carry".to_string(),
            (1.expr() - n_is_zero.clone())
                * (t4.clone()
                    + t5.clone() * pow_of_two::<F>(64)
                    + n[1].clone() * q_overflow.clone()
                    + carry_1.clone()
                    - a_plus_b_hi_carry.clone()),
        ));

        // Constraint t6 + n_hi * q_overflow = 0, when n != 0.
        // And constraint r = 0, when n = 0.
        constraints.push((
            "t6 + n_hi * q_overflow = 0".to_string(),
            (1.expr() - n_is_zero.clone()) * (t6.clone() + n[0].clone() * q_overflow.clone())
                + n_is_zero.clone() * (r[0].clone() + r[1].clone()),
        ));

        constraints
    }
}

// Addmod arithmetic witeness rows. (Tag::Addmod)
// +-------------------+-------------------+-------------+-------------+-----+-------------+
// | operand0          | operand1          | operand2    | operand3    | cnt | u16s        |
// +-------------------+-------------------+-------------+-------------+-----+-------------+
// |                   |                   |             |             | 11  | rn_diff_lo  |
// |                   |                   |             |             | 10  | rn_diff_hi  |
// |                   |                   |             |             | 9   | carry_1     |
// |                   |                   |             |             | 8   | carry_0     |
// |                   |                   |             |             | 7   | a_plus_b_lo |
// |                   |                   |             |             | 6   | a_plus_b_hi |
// | a_plus_b_lo_carry | a_plus_b_hi_carry |             |             | 5   | q_lo        |
// | carry_0           | carry_1           | q_overflow  |             | 4   | q_hi        |
// | q_hi              | q_lo              | a_plus_b_hi | a_plus_b_lo | 3   | n_lo        |
// | rn_carry_lt_hi    | rn_carry_lt_lo    | rn_diff_hi  | rn_diff_lo  | 2   | n_hi        |
// | n_hi              | n_lo              | r_hi        | r_lo        | 1   | r_lo        |
// | a_hi              | a_lo              | b_hi        | b_lo        | 0   | r_hi        |
// +-------------------+-------------------+-------------+-------------+-----+-------------+
//
/// Generate the addmod witness and return operation result
/// It is called during core circuit's gen_witness.
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    // Assert the number of operands is 3
    assert_eq!(3, operands.len());

    // Get the operands a, b, n
    let a = operands[0].clone();
    let b = operands[1].clone();
    let n = operands[2].clone();

    // Calculate the quotient and remainder of a + b divided by n
    let (q_tmp, r_tmp) = if n == U256::zero() {
        (U512::zero(), U512::zero())
    } else {
        (U512::from(a) + U512::from(b)).div_mod(U512::from(n))
    };

    // Note: Here, 'q' refers to the first 256 bits of the quotient,
    // and 'q_overflow' refers to the part that exceeds 256 bits.
    // The same applies to 'a_plus_b'.
    let (q_overflow, q, r): (U256, U256, U256) = if (q_tmp >> 256) == U512::zero() {
        (
            U256::zero(),
            q_tmp.try_into().unwrap(),
            r_tmp.try_into().unwrap(),
        )
    } else {
        (
            U256::from(1),
            q_tmp
                .saturating_sub(U512::from(1) << 256)
                .try_into()
                .unwrap(),
            r_tmp.try_into().unwrap(),
        )
    };

    // Get the u16s for a, b, n, r, q
    let a_split = split_u256_hi_lo(&a);
    let b_split = split_u256_hi_lo(&b);
    let n_split = split_u256_hi_lo(&n);
    let r_split = split_u256_hi_lo(&r);
    let q_split = split_u256_hi_lo(&q);

    // row 0
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // | a_hi           | a_lo           | b_hi        | b_lo              | 0   | r_hi        |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let mut r_u16s: Vec<u16> = r
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let r_u16s_hi = r_u16s.split_off(8);

    let row0 = get_row(a_split, b_split, r_u16s_hi, 0, Tag::Addmod);

    // row 1
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // | n_hi           | n_lo           | r_hi        | r_lo              | 1   | r_lo        |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let row1 = get_row(n_split, r_split, r_u16s, 1, Tag::Addmod);

    // row 2
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // | rn_carry_lt_hi | rn_carry_lt_lo | rn_diff_hi  | rn_diff_lo        | 2   | n_hi        |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let mut n_u16s: Vec<u16> = n
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let n_u16s_hi = n_u16s.split_off(8);

    let (rn_carry_lt, rn_diff_split, rn_diff_u16s) =
        get_lt_word_operations(vec![r.clone(), n.clone()]);
    let row2 = get_row(
        [(rn_carry_lt[0] as u8).into(), (rn_carry_lt[1] as u8).into()],
        rn_diff_split,
        n_u16s_hi.clone(),
        2,
        Tag::Addmod,
    );

    // row 3
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // | q_hi           | q_lo           | a_plus_b_hi | a_plus_b_lo       | 3   | n_lo        |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let (a_plus_b, a_plus_b_hi_carry) = a.overflowing_add(b);
    let a_plus_b_split = split_u256_hi_lo(&a_plus_b);

    let row3 = get_row(q_split, a_plus_b_split, n_u16s.clone(), 3, Tag::Addmod);

    // Construct the gadget that checks n * q + n * q_overflow << 256 + r = a_plus_b_hi_carry << 256 + a_plus_b
    // Where n, q, q_overflow, r, a, b are 256-bit words.
    // And q_overflow and a_plus_b_hi_carry must 0 or 1.
    // We execute a multi-limb multiplication as follows:
    // n and q is divided into 4 64-bit limbs, denoted as n0~n3 and q0~q3
    // defined t0, t1, t2, t3, t4, t5, t6:
    // t0 = n0 * q0,
    // t1 = n0 * q1 + n1 * q0,
    // t2 = n0 * q2 + n1 * q1 + n2 * q0,
    // t3 = n0 * q3 + n1 * q2 + n2 * q1 + n3 * q0,
    // t4 = n1 * q3 + n2 * q2 + n3 * q1,
    // t5 = n2 * q3 + n3 * q2,
    // t6 = n3 * q3,
    //
    // Finally we just prove:
    // t0 + t1 * 2^64 + r_lo = a_plus_b_lo + carry_0 * 2^128                     // 0-127bit
    // t2 + t3 * 2^64 + r_hi + carry_0 = a_plus_b_hi + carry_1 * 2^128           // 128-255bit
    // t4 + t5 * 2^64 + n_lo * q_overflow + carry_1 = a_plus_b_hi_carry          // 256-383bit
    // t6 + n_hi * q_overflow = 0                                                // 384-511bit

    // row 4
    // +-------------------+-------------------+-------------+-------------+-----+-------------+
    // | carry_0           | carry_1           | q_overflow  |             | 4   | q_hi        |
    // +-------------------+-------------------+-------------+-------------+-----+-------------+
    let n_limbs = split_u256_limb64(&n);
    let q_limbs = split_u256_limb64(&q);
    let t0 = n_limbs[0] * q_limbs[0];
    let t1 = n_limbs[0] * q_limbs[1] + n_limbs[1] * q_limbs[0];
    let t2 = n_limbs[0] * q_limbs[2] + n_limbs[1] * q_limbs[1] + n_limbs[2] * q_limbs[0];
    let t3 = n_limbs[0] * q_limbs[3]
        + n_limbs[1] * q_limbs[2]
        + n_limbs[2] * q_limbs[1]
        + n_limbs[3] * q_limbs[0];
    // t4, t5, t6 no need here

    let carry_0 = (t0 + (t1 << 64) + r_split[1]).saturating_sub(a_plus_b_split[1]) >> 128;
    let carry_1 = (t2 + (t3 << 64) + r_split[0] + carry_0).saturating_sub(a_plus_b_split[0]) >> 128;

    let mut q_u16s: Vec<u16> = q
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let q_u16s_hi = q_u16s.split_off(8);

    let row4 = get_row(
        [carry_0, carry_1],
        [q_overflow, U256::zero()],
        q_u16s_hi,
        4,
        Tag::Addmod,
    );

    // row 5
    // +-------------------+-------------------+-------------+-------------+-----+-------------+
    // | a_plus_b_lo_carry | a_plus_b_hi_carry |             |             | 5   | q_lo        |
    // +-------------------+-------------------+-------------+-------------+-----+-------------+
    let a_plus_b_lo_carry = if a_split[1] + b_split[1] > ((U256::from(1) << 128) - 1) {
        U256::one()
    } else {
        U256::zero()
    };
    let row5 = get_row(
        [a_plus_b_lo_carry, (a_plus_b_hi_carry as u8).into()],
        [U256::zero(), U256::zero()],
        q_u16s,
        5,
        Tag::Addmod,
    );

    // row 6
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 6   | a_plus_b_hi |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let mut a_plus_b_u16s: Vec<u16> = a_plus_b
        .clone()
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let a_plus_b_u16s_hi = a_plus_b_u16s.split_off(8);

    let row6 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        a_plus_b_u16s_hi,
        6,
        Tag::Addmod,
    );

    // row 7
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 7   | a_plus_b_lo |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let row7 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        a_plus_b_u16s,
        7,
        Tag::Addmod,
    );

    // row 8
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 8   | carry_0     |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let mut carry_0_u16s: Vec<u16> = carry_0
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_0_u16s.len());
    let _ = carry_0_u16s.split_off(8);

    let row8 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_0_u16s,
        8,
        Tag::Addmod,
    );

    // row 9
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 9   | carry_1     |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let mut carry_1_u16s: Vec<u16> = carry_1
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_1_u16s.len());
    let _ = carry_1_u16s.split_off(8);

    let row9 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        carry_1_u16s,
        9,
        Tag::Addmod,
    );

    // row 10
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 10  | rn_diff_hi  |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let row10 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        rn_diff_u16s[0].clone(),
        10,
        Tag::Addmod,
    );

    // row 11
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    // |                |                |             |                   | 11  | rn_diff_lo  |
    // +----------------+----------------+-------------+-------------------+-----+-------------+
    let row11 = get_row(
        [U256::zero(), U256::zero()],
        [U256::zero(), U256::zero()],
        rn_diff_u16s[1].clone(),
        11,
        Tag::Addmod,
    );

    // return the arithmetic witness and the result
    (
        vec![
            row11, row10, row9, row8, row7, row6, row5, row4, row3, row2, row1, row0,
        ],
        vec![r, U256::zero()],
    )
}

// Create a new AddModGadget
pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(AddModGadget(PhantomData))
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    // Test AddMod witness with usual values.
    // (3 + 4) mod 2 = 1
    #[test]
    fn test_gen_witness() {
        // (a + b) mod n = r when n != 0
        let a = 3.into();
        let b = 4.into();
        let n = 2.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(1));
    }

    // Test AddMod witness with n is zero.
    // (3 + 4) mod 0 = 0
    #[test]
    fn test_gen_witness_1() {
        // (a + b) mod n = r when n == 0
        let a = 3.into();
        let b = 4.into();
        let n = 0.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
    }

    // Test AddMod witness with a and b are U256::MAX.
    // (U256::MAX + U256::MAX) mod 1 = 0
    #[test]
    fn test_gen_witness_2() {
        let a = U256::MAX;
        let b = U256::MAX;
        let n = 1.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::zero());
    }

    // Test AddMod witness with a and b are usual values and n is U256::MAX.
    // (3 + 4) mod U256::MAX = 7
    #[test]
    fn test_gen_witness_3() {
        // (a + b) mod n = r when n != 0
        let a = 3.into();
        let b = 4.into();
        let n = U256::MAX;
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(7));
    }

    // Test AddMod witness with a and b are zero.
    // (0 + 0) mod 1 = 0
    #[test]
    fn test_gen_witness_4() {
        // (a + b) mod n = r when a, b == 0
        let a = 0.into();
        let b = 0.into();
        let n = 1.into();
        let (arithmetic, result) = gen_witness(vec![a, b, n]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
    }
}
