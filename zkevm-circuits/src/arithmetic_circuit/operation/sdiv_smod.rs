use crate::arithmetic_circuit::operation::{
    get_lt_operations, get_lt_word_operations, get_row, get_u16s, OperationConfig, OperationGadget,
    SLT_N_BYTES, S_MAX,
};
use crate::util::convert_f_to_u256;
use crate::util::convert_u256_to_f;

use crate::witness::arithmetic::{Row, Tag};
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_lt_word::SimpleLtWordGadget;
use gadgets::util::{pow_of_two, split_u256_hi_lo, split_u256_limb64, Expr};
use halo2_proofs::halo2curves::bn256::Fr;

use halo2_proofs::plonk::{Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) struct SDivSModGadget<F>(PhantomData<F>);
impl<F: Field> OperationGadget<F> for SDivSModGadget<F> {
    fn name(&self) -> &'static str {
        "SDIV_SMOD"
    }

    fn tag(&self) -> Tag {
        Tag::SdivSmod
    }

    fn num_row(&self) -> usize {
        18
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (18, 1)
    }

    /// formula:
    /// `signed(a) / signed(b) = signed(c) (r) signed(d)`
    /// 1.Construct constraints for negative signs of a, b, c, and d.
    /// 2.Construct constraints for the two's complement of a, b, c, and d.
    /// 3.Construct constraints for mul and constrain the remainder to be less than the divisor.
    /// 4.The dividend and remainder have the same sign when the divisor, quotient, and remainder are all non-zero.
    /// 5.When the two's complement of the dividend is greater than 0 and the quotient and divisor are not equal to 0, constrain the existing sign relationship.
    /// Constrains:
    /// - `lhs - rhs == diff - (lt * range)`, used to determine the sign of a UINT type number.
    /// - complement constrains:
    ///     - `com_lo = lo when operand >= 0`
    ///     - `com_hi == hi when operand >= 0`
    ///     - `com_lo + lo = carry_lo << 128 when operands < 0`
    ///     - `carry_lo is bool`
    ///     - `com_hi + hi + carry_lo = carry_hi << 128 when operands < 0`
    ///     - `carry_hi == 1 when operand < 0`
    /// - div constrains:
    ///     - `b * c + d = a`
    ///     - `carry_hi is 0`
    ///     - `d < b if b != 0`
    /// - signed constrains, The sign of the dividend and remainder is the same.:
    ///     - `a_lt = d_lt`
    fn get_constraints(
        &self,
        config: &OperationConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // get u16s[7]:
        // only need to judge the positive or negative of the operand based on the high 16 bits,
        // without taking out the entire U256 operand.
        let a_rhs = config.get_u16(7, Rotation(-12))(meta);
        let b_rhs = config.get_u16(7, Rotation(-13))(meta);
        let c_rhs = config.get_u16(7, Rotation(-14))(meta);
        let d_rhs = config.get_u16(7, Rotation(-16))(meta);
        let a_com_rhs = config.get_u16(7, Rotation::cur())(meta);
        let rhs = [a_rhs, b_rhs, c_rhs, d_rhs, a_com_rhs];

        // x_diff from `lhs - rhs = diff - (lt * range)`
        // necessary parameters required to build constraints, diff is 16bit
        let a_diff = config.get_u16(0, Rotation(-11))(meta);
        let b_diff = config.get_u16(1, Rotation(-11))(meta);
        let c_diff = config.get_u16(2, Rotation(-11))(meta);
        let d_diff = config.get_u16(3, Rotation(-11))(meta);
        let a_com_diff = config.get_u16(4, Rotation(-11))(meta);
        let diff = [a_diff, b_diff, c_diff, d_diff, a_com_diff];

        //get sum_carry that is the sum of the complement value and the original value
        let a_sum_carry = config.get_operand(24)(meta);
        let b_sum_carry = config.get_operand(25)(meta);
        let c_sum_carry = config.get_operand(26)(meta);
        let d_sum_carry = config.get_operand(27)(meta);
        let sum_carry = [a_sum_carry, b_sum_carry, c_sum_carry, d_sum_carry];

        //get operands a,b,c,d
        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let c = config.get_operand(2)(meta);
        let d = config.get_operand(3)(meta);

        let operands = [a, b, c, d];
        //get operands a_com,b_com,c_com,d_com
        let a_com = config.get_operand(4)(meta);
        let b_com = config.get_operand(5)(meta);
        let c_com = config.get_operand(6)(meta);
        let d_com = config.get_operand(7)(meta);
        let com_operands = [a_com, b_com, c_com, d_com];

        // ab_carry_lt[0] is the sign for dividend. ab_carry_lt[1] is the sign for divisor.
        // cd_carry_lt[0] is the sign for quotient. cd_carry_lt[1] is the sign for remainder.
        let ab_carry_lt = config.get_operand(22)(meta);
        let [a_is_neg, b_is_neg] = ab_carry_lt.clone();
        let cd_carry_lt = config.get_operand(23)(meta);
        let [c_is_neg, d_is_neg] = cd_carry_lt.clone();
        let [a_com_carry_lt, _] = config.get_operand(28)(meta);

        // 1.Construct constraints for negative signs of a, b, c, and d.
        // get_is_neg_constraints used to determine whether the operand is a negative number
        // when carry_lt == 1, the operand is negative number.
        // use `lhs - rhs = diff - lt << 256`, lhs = (2 << 254) - 1, lhs
        // when lt == 1, lhs < rhs --> rhs > (2 << 254) - 1,
        // It means that the number of lhs at position 256 is 1, so it is a negative number.
        let is_neg_constraints = get_is_neg_constraints(
            &ab_carry_lt.clone(),
            &cd_carry_lt.clone(),
            &a_com_carry_lt,
            &rhs,
            &diff,
        );
        constraints.extend(is_neg_constraints);

        // 2.Construct constraints for the two's complement of a, b, c, and d.
        let complement_constraints = get_complement_constraints(
            config,
            meta,
            &ab_carry_lt.clone(),
            &cd_carry_lt.clone(),
            sum_carry.clone(),
            com_operands,
            operands,
        );
        constraints.extend(complement_constraints);

        // 3. Construct constraints for mul and constrain the remainder to be less than the divisor.
        let mul_constraints = get_mul_constraints(config, meta);
        constraints.extend(mul_constraints);

        // 4.The dividend and remainder have the same sign when the divisor, quotient, and remainder are all non-zero.

        let a = config.get_operand(0)(meta);
        let b = config.get_operand(1)(meta);
        let c = config.get_operand(2)(meta);

        // When we use a non-zero value as a condition for judgment,
        // we can directly calculate it using the method similar to a_lo+a_hi.
        // otherwise, the method of using the multiplicative inverse should be used.
        let quotient_not_is_zero = c[0].clone() + c[1].clone(); //if quotient is zero then quotient_is_zero is 0
        let divisor_not_is_zero = b[0].clone() + b[1].clone(); //if divisor is zero then divisor_is_zero is 0
        let dividend_not_is_zero = a[0].clone() + a[1].clone(); //if dividend is zero then dividend_is_zero is 0

        let [div_zero_flag, _] = config.get_operand(8)(meta);
        // constraint div_zero_flag = divisor_not_is_zero * dividend_not_is_zero
        constraints.push((
            "div_zero_flag = divisor_not_is_zero * dividend_not_is_zero".to_string(),
            div_zero_flag.clone() - (divisor_not_is_zero.clone() * dividend_not_is_zero.clone()),
        ));

        constraints.push((
            "sign(dividend) == sign(remainder) when divisor and remainder are all non-zero"
                .to_string(),
            div_zero_flag.clone() * (a_is_neg.clone() - d_is_neg.clone()),
        ));

        //5.Computes sign relations with sign multiplication
        let [a_com_carry_lt, _] = config.get_operand(28)(meta);

        let [b_c_is_neg, _]: [Expression<F>; 2] = config.get_operand(29)(meta);

        // constraints that mul_signed_operand = c_is_neg + b_is_neg - a_is_neg - 2 * c_is_neg * b_is_neg
        constraints.push((
            "b_c_is_neg = c_is_neg * b_is_neg".to_string(),
            b_c_is_neg.clone() - c_is_neg.clone() * b_is_neg.clone(),
        ));

        // Computes sign relations with sign multiplication
        // Satisfying negative multiplied by negative equals positive,
        // negative multiplied by positive equals negative.
        let mul_signed =
            c_is_neg.clone() + b_is_neg.clone() - a_is_neg.clone() - 2.expr() * b_c_is_neg.clone();

        let [signed, _] = config.get_operand(30)(meta);
        // constraint signed = quotient_not_is_zero * (1.expr() - a_com_carry_lt.clone())
        constraints.push((
            "signed = quotient_not_is_zero * (1.expr() - a_com_carry_lt.clone())".to_string(),
            signed.clone() - quotient_not_is_zero.clone() * (1.expr() - a_com_carry_lt.clone()),
        ));

        constraints.push((
            "sign(dividend) == sign(divisor) ^ sign(quotient)".to_string(),
            signed.clone() * mul_signed.clone(),
        ));
        constraints
    }
}

/// SDiv_SMod arithmetic witness rows. (Tag::SDiv_SMod)
/// +-----+----------------+----------------+----------------+----------------+----------------+---------+---------+---------+------------+
/// | cnt | op_0_hi        | op_0_lo        | op_1_hi        | op_1_lo        | u16s_0         | u16s_1  |         |         |            |
/// +-----+----------------+----------------+----------------+----------------+----------------+---------+---------+---------+------------+
/// | 17  |                |                |                |                | d_lo_0         |         |         |         |            |
/// | 16  |                |                |                |                | d_hi_0         |         |         |         |            |
/// | 15  | signed         |                |                |                | c_lo_0         |         |         |         |            |
/// | 14  | a_com_lt       |                | b_c_is_neg     |                | c_hi_0         |         |         |         |            |
/// | 13  | c_sum_carry_hi | c_sum_carry_lo | d_sum_carry_hi | d_sum_carry_lo | b_hi_0         |         |         |         |            |
/// | 12  | a_sum_carry_hi | a_sum_carry_lo | b_sum_carry_hi | b_sum_carry_lo | a_hi_0         |         |         |         |            |
/// | 11  | a_lt_carry_hi  | b_lt_carry_hi  | c_lt_carry_hi  | d_lt_carry_hi  | a_diff         | b_diff  | c_diff  | d_diff  | a_com_diff |
/// | 10  |                |                |                |                | cb_diff_lo_0   |         |         |         |            |  
/// | 9   | db_diff_hi     | db_diff_lo     | db_carry_hi    | db_carry_lo    | cb_diff_hi_0   |         |         |         |            |
/// |     | (cb is d < b)  |                |                |                |                |         |         |         |            |
/// | 8   | mul_carry_hi   | mul_carry_lo   |                |                | mul_carry_lo_0 |         |         |         |            |
/// | 7   |                |                |                |                | d_com_lo_0     |         |         |         |            |
/// | 6   |                |                |                |                | d_com_hi_0     |         |         |         |            |
/// | 5   |                |                |                |                | c_com_lo_0     |         |         |         |            |
/// | 4   | div_zero_flag  |                |                |                | c_com_hi_0     |         |         |         |            |
/// | 3   | c_com_hi       | c_com_lo       | d_com_hi       | d_com_lo       | b_com_lo_0     |         |         |         |            |
/// | 2   | a_com_hi       | a_com_lo       | b_com_hi       | b_com_lo       | b_com_hi_0     |         |         |         |            |
/// | 1   | c_hi           | c_lo           | d_hi           | d_lo           | a_com_lo_0     |         |         |         |            |
/// | 0   | a_hi           | a_lo           | b_hi           | d_lo           | a_com_hi_0     |         |         |         |            |
/// +-----+----------------+----------------+----------------+----------------+----------------+---------+---------+---------+------------+

/// Generate the witness and return operation result
/// It is called during core circuit's gen_witness
/// Returns the remainder and quotient,
/// and the external call determines the division and remainder based on the opcode.
pub(crate) fn gen_witness(operands: Vec<U256>) -> (Vec<Row>, Vec<U256>) {
    assert_eq!(2, operands.len());

    let (args, rows) = gen_sign_div_mod_witness(operands.clone(), Tag::SdivSmod);

    //Calculate the sum of the original value and the complement
    //get a_com_hi,a_com_lo and a_hi,a_lo sum
    let a_carry = get_sum_carry(
        operands[0].clone(),
        [args[1][1], args[1][2]],
        [args[0][1], args[0][2]],
    );
    //get b_com_hi,b_com_lo and b_hi,b_lo sum
    let b_carry = get_sum_carry(
        operands[1].clone(),
        [args[1][4], args[1][5]],
        [args[0][4], args[0][5]],
    );
    //get c_com_hi,c_com_lo and c_hi,c_lo sum
    let c_carry = get_sum_carry(
        args[2][0],
        [args[3][1], args[3][2]],
        [args[2][1], args[2][2]],
    );
    //get d_com_hi,d_com_lo and d_hi,d_lo sum
    let d_carry = get_sum_carry(
        args[2][3],
        [args[3][4], args[3][5]],
        [args[2][4], args[2][5]],
    );

    let sum_carry = [a_carry, b_carry, c_carry, d_carry];
    let com_operands = [
        operands[0].clone(),
        operands[1].clone(),
        args[2][0],
        args[2][3],
        args[1][1],
    ];

    // The value to be allocated for obtaining the complement code.
    let com_rows = gen_com_witness(com_operands, sum_carry, Tag::SdivSmod);

    let mut result_rows = vec![];
    result_rows.extend(com_rows);
    result_rows.extend(rows);

    let mod_v = if operands[1] == U256::zero() {
        U256::zero()
    } else {
        args[2][3]
    }; //set mod value

    (result_rows, vec![mod_v, args[2][0]])
}

pub(crate) fn new<F: Field>() -> Box<dyn OperationGadget<F>> {
    Box::new(SDivSModGadget(PhantomData))
}

/// Calculate the sum of the complement value and the original value。if x > 0, then return (0,0) else return (carry_hi,carry_lo)
fn get_sum_carry(operand: U256, com: [U256; 2], original: [U256; 2]) -> (U256, U256) {
    let (a_sum_carry_hi, a_sum_carry_lo) = if is_neg(operand) {
        let a_sum_carry_lo = (original[1] + com[1]) >> 128;
        let a_sum_carry_hi = (original[0] + com[0] + a_sum_carry_lo) >> 128;

        (a_sum_carry_hi, a_sum_carry_lo)
    } else {
        (U256::zero(), U256::zero())
    };

    (a_sum_carry_hi, a_sum_carry_lo)
}

/// Generate witness information related to the constraint of the complement value and the original value。
/// operands[0] is a_hi, operands[1] is b_hi, operands[2] is c, operands[3] is d, operands[4] is a_com_hi
/// sum_carry is the sum of the complement value and the original value
/// This method generate witness rows of numbered 11 through 17
pub fn gen_com_witness(operands: [U256; 5], sum_carry: [(U256, U256); 4], tag: Tag) -> Vec<Row> {
    //get u16s of a,b,c,d and a complement
    let mut a_u16s: Vec<u16> = operands[0]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let a_hi_u16s = a_u16s.split_off(8);
    assert_eq!(8, a_hi_u16s.len());

    let mut b_u16s: Vec<u16> = operands[1]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let b_hi_u16s = b_u16s.split_off(8);
    assert_eq!(8, b_hi_u16s.len());

    let mut c_u16s: Vec<u16> = operands[2]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, c_u16s.len());
    let c_hi_u16s = c_u16s.split_off(8);

    let mut d_u16s: Vec<u16> = operands[3]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, d_u16s.len());
    let d_hi_u16s = d_u16s.split_off(8);

    let mut a_com_hi_u16s: Vec<u16> = operands[4]
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    let _ = a_com_hi_u16s.split_off(8);
    assert_eq!(8, a_com_hi_u16s.len());

    // Get whether a,b,c,d,a complement is neg
    let range = U256::from(2).pow(U256::from(SLT_N_BYTES * 8));

    let (a_lt, a_diff, _) = get_lt_operations(
        &U256::from(S_MAX),
        &U256::from(a_hi_u16s[7].clone()),
        &range,
    );
    let (b_lt, b_diff, _) = get_lt_operations(
        &U256::from(S_MAX),
        &U256::from(b_hi_u16s[7].clone()),
        &range,
    );
    let (c_lt, c_diff, _) = get_lt_operations(
        &U256::from(S_MAX),
        &U256::from(c_hi_u16s[7].clone()),
        &range,
    );
    let (d_lt, d_diff, _) = get_lt_operations(
        &U256::from(S_MAX),
        &U256::from(d_hi_u16s[7].clone()),
        &range,
    );
    let (a_com_lt, a_com_diff, _) = get_lt_operations(
        &U256::from(S_MAX),
        &U256::from(a_com_hi_u16s[7].clone()),
        &range,
    );

    let row_11 = Row {
        tag: tag,
        cnt: 11.into(),
        operand_0_hi: U256::from(a_lt as i8),
        operand_0_lo: U256::from(b_lt as i8),
        operand_1_hi: U256::from(c_lt as i8),
        operand_1_lo: U256::from(d_lt as i8),
        u16_0: a_diff,
        u16_1: b_diff,
        u16_2: c_diff,
        u16_3: d_diff,
        u16_4: a_com_diff,
        u16_5: 0.into(),
        u16_6: 0.into(),
        u16_7: 0.into(),
    };

    let row_12 = get_row(
        [sum_carry[0].0, sum_carry[0].1],
        [sum_carry[1].0, sum_carry[1].1],
        a_hi_u16s,
        12,
        tag,
    );

    let row_13 = get_row(
        [sum_carry[2].0, sum_carry[2].1],
        [sum_carry[3].1, sum_carry[3].1],
        b_hi_u16s,
        13,
        tag,
    );

    // Computes sign relations with sign multiplication
    // Satisfying negative multiplied by negative equals positive,
    // negative multiplied by positive equals negative.

    let b_c_is_neg = U256::from(c_lt as i8) * U256::from(b_lt as i8);
    let row_14 = get_row(
        [U256::from(a_com_lt as i8), U256::zero()],
        [b_c_is_neg, U256::zero()],
        c_hi_u16s,
        14,
        tag,
    );

    let c_slice = split_u256_hi_lo(&operands[2]);
    let quotient_not_is_zero = c_slice[0] + c_slice[1];

    let quotient_not_is_zero_f = convert_u256_to_f::<Fr>(&quotient_not_is_zero);

    let a_com_carry_lt = U256::from(a_com_lt as i8);
    let a_com_carry_lt_f = convert_u256_to_f::<Fr>(&a_com_carry_lt);

    let signed_f = quotient_not_is_zero_f * (Fr::one() - a_com_carry_lt_f);
    let signed = convert_f_to_u256(&signed_f);

    let row_15 = get_row([signed, U256::zero()], [U256::zero(); 2], c_u16s, 15, tag);

    let row_16 = get_row([U256::zero(); 2], [U256::zero(); 2], d_hi_u16s, 16, tag);

    let row_17 = get_row([U256::zero(); 2], [U256::zero(); 2], d_u16s, 17, tag);

    vec![row_17, row_16, row_15, row_14, row_13, row_12, row_11]
}

/// calculate signed div_mod
/// This method generate witness rows of numbered 0 through 10
fn gen_sign_div_mod_witness(operands: Vec<U256>, tag: Tag) -> ([[U256; 6]; 4], Vec<Row>) {
    assert_eq!(2, operands.len());
    //get a,b complement
    let a_com = get_com(operands[0]);
    let b_com = get_com(operands[1]);
    let a_com_slice = split_u256_hi_lo(&a_com);
    let b_com_slice = split_u256_hi_lo(&b_com);
    let ab_com = [
        a_com,
        a_com_slice[0],
        a_com_slice[1],
        b_com,
        b_com_slice[0],
        b_com_slice[1],
    ];

    //calculate a_com / b_com when b_com == 0 set d_com == a_com
    let (c_com, d_com) = if operands[1] == U256::zero() {
        (U256::zero(), a_com.clone())
    } else {
        a_com.div_mod(b_com)
    };

    let c_com_slice = split_u256_hi_lo(&c_com);
    let d_com_slice = split_u256_hi_lo(&d_com);
    let cd_com = [
        c_com,
        c_com_slice[0],
        c_com_slice[1],
        d_com,
        d_com_slice[0],
        d_com_slice[1],
    ];

    // c,d is the extend value of div and mod operation. In mod, the remainder has the same sign as the dividend.
    let (c, d) = if is_neg(operands[0]) {
        if !is_neg(operands[1]) {
            (get_neg(c_com), get_neg(d_com))
        } else {
            (c_com, get_neg(d_com))
        }
    } else {
        if is_neg(operands[1]) {
            (get_neg(c_com), d_com)
        } else {
            (c_com, d_com)
        }
    };
    let c_slice = split_u256_hi_lo(&c);
    let d_slice = split_u256_hi_lo(&d);
    let cd = [c, c_slice[0], c_slice[1], d, d_slice[0], d_slice[1]];

    //get u16s of a,b,c,d complement
    let mut a_com_u16s: Vec<u16> = a_com
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, a_com_u16s.len());

    let mut b_com_u16s: Vec<u16> = b_com
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, b_com_u16s.len());

    let mut c_com_u16s: Vec<u16> = c_com
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, c_com_u16s.len());

    let mut d_com_u16s: Vec<u16> = d_com
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, d_com_u16s.len());

    let a_slice = split_u256_hi_lo(&operands[0]);
    let b_slice = split_u256_hi_lo(&operands[1]);
    let ab = [
        operands[0],
        a_slice[0],
        a_slice[1],
        operands[1],
        b_slice[0],
        b_slice[1],
    ];

    //build a,b,c,d complement rows
    let a_com_hi_u16s = a_com_u16s.split_off(8);
    let row_0 = get_row(a_slice, b_slice, a_com_hi_u16s, 0, tag);
    let row_1 = get_row(c_slice, d_slice, a_com_u16s, 1, tag);

    let b_com_hi_u16s = b_com_u16s.split_off(8);
    let row_2 = get_row(a_com_slice, b_com_slice, b_com_hi_u16s, 2, tag);
    let row_3 = get_row(c_com_slice, d_com_slice, b_com_u16s, 3, tag);

    let c_com_hi_u16s = c_com_u16s.split_off(8);

    let tmp_a = a_slice[0] + a_slice[1];
    let tmp_b = b_slice[0] + b_slice[1];
    let tmp_a_f = convert_u256_to_f::<Fr>(&tmp_a);
    let tmp_b_f = convert_u256_to_f::<Fr>(&tmp_b);

    let div_zero_flag_f = tmp_a_f * tmp_b_f;
    let row_4 = get_row(
        [convert_f_to_u256::<Fr>(&div_zero_flag_f), U256::zero()],
        [U256::zero(); 2],
        c_com_hi_u16s,
        4,
        tag,
    );
    let row_5 = get_row([U256::zero(); 2], [U256::zero(); 2], c_com_u16s, 5, tag);

    let d_com_hi_u16s = d_com_u16s.split_off(8);
    let row_6 = get_row([U256::zero(); 2], [U256::zero(); 2], d_com_hi_u16s, 6, tag);
    let row_7 = get_row([U256::zero(); 2], [U256::zero(); 2], d_com_u16s, 7, tag);

    // Calculate the overflow of multiplication. carry_hi and carry_lo
    let c_limbs = split_u256_limb64(&c_com);
    let b_limbs = split_u256_limb64(&b_com);

    //detail please see mul.rs
    let t0 = c_limbs[0] * b_limbs[0];
    let t1 = c_limbs[0] * b_limbs[1] + c_limbs[1] * b_limbs[0];
    let t2 = c_limbs[0] * b_limbs[2] + c_limbs[1] * b_limbs[1] + c_limbs[2] * b_limbs[0];
    let t3 = c_limbs[0] * b_limbs[3]
        + c_limbs[1] * b_limbs[2]
        + c_limbs[2] * b_limbs[1]
        + c_limbs[3] * b_limbs[0];

    let carry_lo = (t0 + (t1 << 64) + d_com_slice[1]).saturating_sub(a_com_slice[1]) >> 128;
    let carry_hi =
        (t2 + (t3 << 64) + d_com_slice[0] + carry_lo).saturating_sub(a_com_slice[0]) >> 128;

    let mut carry_lo_u16s: Vec<u16> = carry_lo
        .to_le_bytes()
        .chunks(2)
        .map(|x| x[0] as u16 + x[1] as u16 * 256)
        .collect();
    assert_eq!(16, carry_lo_u16s.len());

    let _ = carry_lo_u16s.split_off(8);
    let row_8 = get_row(
        [carry_hi, carry_lo],
        [U256::zero(); 2],
        carry_lo_u16s,
        8,
        tag,
    );

    let db_rows = get_lt_word_rows(vec![d_com, b_com]);

    let rows = vec![
        db_rows[0].clone(),
        db_rows[1].clone(),
        row_8,
        row_7,
        row_6,
        row_5,
        row_4,
        row_3,
        row_2,
        row_1,
        row_0,
    ];
    ([ab, ab_com, cd, cd_com], rows)
}

///get operands[0] < operands[1] rows
fn get_lt_word_rows(operands: Vec<U256>) -> Vec<Row> {
    let (carry, diff_split, diff_u16s) = get_lt_word_operations(operands);
    let row_10 = get_row(
        [U256::zero(); 2],
        [U256::zero(); 2],
        diff_u16s[1].clone(),
        10,
        Tag::SdivSmod,
    );

    let row_9 = get_row(
        diff_split,
        [(carry[0] as u8).into(), (carry[1] as u8).into()],
        diff_u16s[0].clone(),
        9,
        Tag::SdivSmod,
    );

    vec![row_10, row_9]
}

/// Generate the complement constraints for the operation.
///       -  x_com_lo == lo when x >= 0
///        - x_com_hi == hi when x >= 0
///        - sum == 0 when x < 0 （小于0证明存在补码,同时我们有x+x_abs = 1 <<256。x + x_abs 约束请参考add部分）
///        - carry_hi == 1 when x < 0
fn complement_constraints<F: Field>(
    operands: [Expression<F>; 2],
    com_operands: [Expression<F>; 2],
    is_neg: Expression<F>,
    carry: [Expression<F>; 2],
    prefix: String,
) -> Vec<(String, Expression<F>)> {
    let mut constraints = vec![];

    constraints.push((
        format!("value_{} com_lo == lo when operand >= 0", prefix),
        (com_operands[1].clone() - operands[1].clone()) * (1.expr() - is_neg.expr()),
    ));
    constraints.push((
        format!("value_{} com_hi == hi when operand >= 0", prefix),
        (com_operands[0].clone() - operands[0].clone()) * (1.expr() - is_neg.expr()),
    ));
    constraints.push((
        format!(
            "value_{} com_lo + lo = carry_lo << 128 when operands < 0",
            prefix
        ),
        ((com_operands[1].clone() + operands[1].clone()) - carry[1].clone() * pow_of_two::<F>(128))
            * is_neg.expr(),
    ));
    constraints.push((
        format!("value_{} carry_lo is bool", prefix),
        carry[1].clone() * (1.expr() - carry[1].clone()),
    ));
    constraints.push((
        format!(
            "value_{} com_hi + hi + carry_lo = carry_hi << 128 when operands < 0",
            prefix
        ),
        ((com_operands[0].clone() + operands[0].clone() + carry[1].clone())
            - carry[0].clone() * pow_of_two::<F>(128))
            * is_neg.expr(),
    ));
    constraints.push((
        format!("value_{} carry_hi == 1 when operand < 0", prefix),
        (carry[0].clone() - 1.expr()) * is_neg.expr(),
    ));

    constraints
}

///Generate the constraints for the is_neg operation.
fn get_is_neg_constraints<F: Field>(
    ab_carry_lt: &[Expression<F>; 2],
    cd_carry_lt: &[Expression<F>; 2],
    a_com_carry_lt: &Expression<F>,
    rhs: &[Expression<F>; 5],
    diff: &[Expression<F>; 5],
) -> Vec<(String, Expression<F>)> {
    let mut constraints = vec![];

    let [a_is_neg, b_is_neg] = ab_carry_lt;
    let [c_is_neg, d_is_neg] = cd_carry_lt;

    let [a_rhs, b_rhs, c_rhs, d_rhs, a_com_rhs] = rhs;
    let [a_diff, b_diff, c_diff, d_diff, a_com_diff] = diff;
    //generate the SimpleLtGadget.
    let lhs = Expression::Constant(F::from(S_MAX));
    let a_is_neg: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&lhs, &a_rhs, &a_is_neg, &a_diff);
    let b_is_neg: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&lhs, &b_rhs, &b_is_neg, &b_diff);
    let c_is_neg: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&lhs, &c_rhs, &c_is_neg, &c_diff);
    let d_is_neg: SimpleLtGadget<F, 2> = SimpleLtGadget::new(&lhs, &d_rhs, &d_is_neg, &d_diff);
    let a_com_is_neg: SimpleLtGadget<F, 2> =
        SimpleLtGadget::new(&lhs, &a_com_rhs, a_com_carry_lt, &a_com_diff);

    constraints.extend(a_is_neg.get_constraints());
    constraints.extend(b_is_neg.get_constraints());
    constraints.extend(c_is_neg.get_constraints());
    constraints.extend(d_is_neg.get_constraints());
    constraints.extend(a_com_is_neg.get_constraints());

    constraints
}

///generate constraints of the complement value and the original value
fn get_complement_constraints<F: Field>(
    config: &OperationConfig<F>,
    meta: &mut VirtualCells<F>,
    ab_carry_lt: &[Expression<F>; 2],
    cd_carry_lt: &[Expression<F>; 2],
    sum_carry: [[Expression<F>; 2]; 4],
    com_operands: [[Expression<F>; 2]; 4],
    operands: [[Expression<F>; 2]; 4],
) -> Vec<(String, Expression<F>)> {
    let mut constraints = vec![];

    //get carry_lt
    let [a_is_neg, b_is_neg] = ab_carry_lt;
    let [c_is_neg, d_is_neg] = cd_carry_lt;

    //get sum_carry that is the sum of the complement value and the original value
    let [a_sum_carry, b_sum_carry, c_sum_carry, d_sum_carry] = sum_carry;

    //get operands a,b,c,d
    let [a, b, c, d] = operands;

    //get operands a_com,b_com,c_com,d_com
    let [a_com, b_com, c_com, d_com] = com_operands;

    //generate complement_constraints for a,b,c,d
    let a_com_constraints = complement_constraints(
        a.clone(),
        a_com.clone(),
        a_is_neg.clone(),
        a_sum_carry,
        "a".to_string(),
    );
    let b_com_constraints = complement_constraints(
        b.clone(),
        b_com.clone(),
        b_is_neg.clone(),
        b_sum_carry,
        "b".to_string(),
    );
    let c_com_constraints = complement_constraints(
        c.clone(),
        c_com.clone(),
        c_is_neg.clone(),
        c_sum_carry,
        "c".to_string(),
    );
    let d_com_constraints = complement_constraints(
        d.clone(),
        d_com.clone(),
        d_is_neg.clone(),
        d_sum_carry,
        "d".to_string(),
    );

    constraints.extend(a_com_constraints);
    constraints.extend(b_com_constraints);
    constraints.extend(c_com_constraints);
    constraints.extend(d_com_constraints);

    let (u16_sum_for_a_hi, _, _) = get_u16s(config, meta, Rotation(-12));
    let (u16_sum_for_b_hi, _, _) = get_u16s(config, meta, Rotation(-13));
    let (u16_sum_for_c_hi, _, _) = get_u16s(config, meta, Rotation(-14));
    let (u16_sum_for_c_lo, _, _) = get_u16s(config, meta, Rotation(-15));
    let (u16_sum_for_d_hi, _, _) = get_u16s(config, meta, Rotation(-16));
    let (u16_sum_for_d_lo, _, _) = get_u16s(config, meta, Rotation(-17));

    //constraints range
    constraints.push((
        "a_hi = u16 sum".to_string(),
        a[0].clone() - u16_sum_for_a_hi,
    ));
    constraints.push((
        "b_hi = u16 sum".to_string(),
        b[0].clone() - u16_sum_for_b_hi,
    ));
    constraints.push((
        "c_hi = u16 sum".to_string(),
        c[0].clone() - u16_sum_for_c_hi,
    ));
    constraints.push((
        "c_lo = u16 sum".to_string(),
        c[1].clone() - u16_sum_for_c_lo,
    ));
    constraints.push((
        "d_hi = u16 sum".to_string(),
        d[0].clone() - u16_sum_for_d_hi,
    ));
    constraints.push((
        "d_lo = u16 sum".to_string(),
        d[1].clone() - u16_sum_for_d_lo,
    ));

    constraints
}

///Generate the constraints for the mul operation.
fn get_mul_constraints<F: Field>(
    config: &OperationConfig<F>,
    meta: &mut VirtualCells<F>,
) -> Vec<(String, Expression<F>)> {
    let mut constraints = vec![];

    // get operands a_com,b_com,c_com,d_com and carry,diff,carry_lt
    let a_com = config.get_operand(4)(meta);
    let b_com = config.get_operand(5)(meta);
    let c_com = config.get_operand(6)(meta);
    let d_com = config.get_operand(7)(meta);
    let carry = config.get_operand(16)(meta);
    let diff = config.get_operand(18)(meta);
    let carry_lt = config.get_operand(19)(meta);

    // get the u16s sum for a,b,c,d and diff,carry_lo
    let (u16_sum_for_a_com_hi, _, _) = get_u16s(config, meta, Rotation::cur());
    let (u16_sum_for_a_com_lo, _, _) = get_u16s(config, meta, Rotation::prev());

    let (u16_sum_for_b_com_hi, b_com_hi_1, b_com_hi_2) = get_u16s(config, meta, Rotation(-2));
    let (u16_sum_for_b_com_lo, b_com_lo_1, b_com_lo_2) = get_u16s(config, meta, Rotation(-3));

    let (u16_sum_for_c_com_hi, c_com_hi_1, c_com_hi_2) = get_u16s(config, meta, Rotation(-4));
    let (u16_sum_for_c_com_lo, c_com_lo_1, c_com_lo_2) = get_u16s(config, meta, Rotation(-5));

    let (u16_sum_for_d_com_hi, _, _) = get_u16s(config, meta, Rotation(-6));
    let (u16_sum_for_d_com_lo, _, _) = get_u16s(config, meta, Rotation(-7));

    //get the u16s sum for carry_lo
    let (u16_sum_for_carry_lo, _, _) = get_u16s(config, meta, Rotation(-8));

    let (u16_sum_for_diff_hi, _, _) = get_u16s(config, meta, Rotation(-9));
    let (u16_sum_for_diff_lo, _, _) = get_u16s(config, meta, Rotation(-10));

    // calculate the t0,t1,t2,t3 for carry_lo and carry_hi
    let mut c_limbs = vec![];
    let mut b_limbs = vec![];
    c_limbs.extend([c_com_lo_1, c_com_lo_2, c_com_hi_1, c_com_hi_2]);
    b_limbs.extend([b_com_lo_1, b_com_lo_2, b_com_hi_1, b_com_hi_2]);

    let t0 = c_limbs[0].clone() * b_limbs[0].clone();
    let t1 = c_limbs[0].clone() * b_limbs[1].clone() + c_limbs[1].clone() * b_limbs[0].clone();
    let t2 = c_limbs[0].clone() * b_limbs[2].clone()
        + c_limbs[1].clone() * b_limbs[1].clone()
        + c_limbs[2].clone() * b_limbs[0].clone();
    let t3 = c_limbs[0].clone() * b_limbs[3].clone()
        + c_limbs[1].clone() * b_limbs[2].clone()
        + c_limbs[2].clone() * b_limbs[1].clone()
        + c_limbs[3].clone() * b_limbs[0].clone();
    let t4 = c_limbs[1].clone() * b_limbs[3].clone()
        + c_limbs[2].clone() * b_limbs[2].clone()
        + c_limbs[3].clone() * b_limbs[1].clone();
    let t5 = c_limbs[2].clone() * b_limbs[3].clone() + c_limbs[3].clone() * b_limbs[2].clone();
    let t6 = c_limbs[3].clone() * b_limbs[3].clone();

    // when carrying, ensure that carry_lo is within the 65-bit range
    constraints.push((
        "carry_lo = u16 sum".to_string(),
        carry[1].clone() - u16_sum_for_carry_lo.clone(),
    ));

    // carry_hi == 0 in division, because 'a' as the dividend is 256-bit
    constraints.push(("carry_hi == 0 ".to_string(), carry[0].clone()));
    // Product higher than 256 bits should be 0
    constraints.push((
        "product higher than 256 bits == 0".to_string(),
        t4.expr() + t5.expr() + t6.expr(),
    ));

    constraints.push((
        "(c_com * b_com)_lo + d_com_lo == a_com_lo + carry_lo * 128".to_string(),
        (t0.expr() + (t1.expr() * pow_of_two::<F>(64))) + d_com[1].clone()
            - a_com[1].clone()
            - carry[1].clone() * pow_of_two::<F>(128),
    ));
    constraints.push((
        "(c_com * b_com)_hi + d_com_hi + carry_lo == a_com_hi ".to_string(),
        (t2.expr() + t3.expr() * pow_of_two::<F>(64)) + d_com[0].clone() + carry[1].clone()
            - a_com[0].clone(),
    ));

    let is_lt_lo = SimpleLtGadget::new(&d_com[1], &b_com[1], &carry_lt[1], &diff[1]);
    let is_lt = SimpleLtWordGadget::new(&d_com[0], &b_com[0], &carry_lt[0], &diff[0], is_lt_lo);

    // constraint c_com < b_com if b_com!=0
    constraints.extend(is_lt.get_constraints());
    constraints.push((
        "d_com < b_com if b_com!=0 ".to_string(),
        (1.expr() - is_lt.expr()) * (b_com[0].clone() + b_com[1].clone()),
    ));

    let u16_sum_for_a_com = [u16_sum_for_a_com_hi, u16_sum_for_a_com_lo];
    let u16_sum_for_b_com = [u16_sum_for_b_com_hi, u16_sum_for_b_com_lo];
    let u16_sum_for_c_com = [u16_sum_for_c_com_hi, u16_sum_for_c_com_lo];
    let u16_sum_for_d_com = [u16_sum_for_d_com_hi, u16_sum_for_d_com_lo];
    let u16_sum_for_diff = [u16_sum_for_diff_hi, u16_sum_for_diff_lo];

    //constraints range of a_com,b_com,c_com,d_com and diff
    for i in 0..2 {
        let hi_or_lo = if i == 0 { "hi" } else { "lo" };
        constraints.push((
            format!("a_com_{} = u16 sum", hi_or_lo),
            a_com[i].clone() - u16_sum_for_a_com[i].clone(),
        ));
        constraints.push((
            format!("b_com_{} = u16 sum", hi_or_lo),
            b_com[i].clone() - u16_sum_for_b_com[i].clone(),
        ));
        constraints.push((
            format!("c_com_{} = u16 sum", hi_or_lo),
            c_com[i].clone() - u16_sum_for_c_com[i].clone(),
        ));
        constraints.push((
            format!("d_com_{} = u16 sum", hi_or_lo),
            d_com[i].clone() - u16_sum_for_d_com[i].clone(),
        ));
        //constrain the diff range
        constraints.push((
            format!("diff_{} = u16 sum", hi_or_lo),
            diff[i].clone() - u16_sum_for_diff[i].clone(),
        ));
    }

    constraints
}

///get complement of x
#[inline]
fn get_com(x: U256) -> U256 {
    if is_neg(x) {
        get_neg(x)
    } else {
        x
    }
}

///get complement of x
#[inline]
fn get_neg(x: U256) -> U256 {
    if x.is_zero() {
        x
    } else {
        U256::MAX - x + U256::from(1)
    }
}

///check x is negative
#[inline]
fn is_neg(x: U256) -> bool {
    127 < x.to_le_bytes()[31]
}

#[cfg(test)]
mod test {
    use super::gen_witness;
    use crate::witness::Witness;
    use eth_types::U256;

    #[test]
    //divisor and dividend  all not zero
    fn test_gen_witness() {
        let a = 3.into();
        let b = u128::MAX.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(3));
        assert_eq!(result[1], U256::from(0));
    }

    #[test]
    // divisor is zero
    fn test_gen_witness_1() {
        let a = U256::MAX;
        let b = 0.into();
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
        assert_eq!(result[1], U256::from(0));
    }

    #[test]
    //dividend is zero
    fn test_gen_witness_2() {
        let a = U256::zero();
        let b = U256::MAX;
        let (arithmetic, result) = gen_witness(vec![a, b]);
        let witness = Witness {
            arithmetic,
            ..Default::default()
        };

        witness.print_csv();
        assert_eq!(result[0], U256::from(0));
        assert_eq!(result[1], U256::from(0));
    }
}
