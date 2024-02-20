use std::ops::{Add, Mul};

use eth_types::U256;
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};

use crate::arithmetic_circuit::operation;

use super::arithmetic;

#[derive(Clone, Debug, Serialize)]
pub struct Row {
    // type of row, one of zero, one, square or bit
    pub tag: Tag,
    // base of exp
    pub base_hi: U256,
    pub base_lo: U256,
    // index of exp
    pub index_hi: U256,
    pub index_lo: U256,
    // count of index
    pub count: U256,
    // whether count is equal or large than 2**128
    // pub is_high: U256,
    // exp res
    pub power_hi: U256,
    pub power_lo: U256,
}

// if tag is ZERO then index is 0 and val is 1
impl Default for Row {
    fn default() -> Self {
        Self {
            tag: Tag::Zero,
            base_hi: U256::zero(),
            base_lo: U256::zero(),
            index_hi: U256::zero(),
            index_lo: U256::zero(),
            count: U256::zero(),
            // is_high: U256::zero(),
            power_hi: U256::zero(),
            power_lo: U256::one(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    #[default]
    Zero,
    One,
    Square,
    Bit0, // index & 1 = 0
    Bit1, // index & 1 = 1
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

impl Row {
    /// from_operands_new generate exp witness, and used arithmetic of mul and add witness
    /// return data:
    ///     power value
    ///     exp rows
    ///     mul rows
    /// algorithm:
    /// 1. generate Tag::Zero row , append to exp rows
    /// 2. if index == 0 , return
    /// 3. generate Tag::One Row , append to exp rows
    /// 4. let (div,rem) = index in   div_mod(2);
    ///       4.1 generate Tag::Bit row
    ///           count = count of pre row
    ///           is_high = is_high of pre row
    ///          4.1.1 if rem == 0 , generate Tag::Bit0 row, append to exp rows
    ///                 index hi/lo = pre_pre index hi/lo
    ///                 power hi/lo = pre_pre power hi/lo
    ///          4.1.2 if rem == 1 , generate Tag::Bit1 row, append to exp rows
    ///                 index hi/lo = sum of index hi/lo of pre_pre row and pre row
    ///                 power hi/lo = mul of power hi/lo of pre_pre row and pre row, and generate arithmetic mul rows append to mul rows
    ///
    ///       if div == 0 break;
    ///      
    ///       4.2 generate Tag::Square Row, append to exp rows
    ///           index hi/lo = pre_pre index hi/lo * 2
    ///           power hi/lo = pre_pre power hi/lo ^ 2 ,and generate arithmetic mul rows, append to mul rows
    ///           count = pre_count + 1
    ///           if count = 128, index hi = 1; index lo = 0
    /// 5. power of hi , power of low of last row of exp rows as final power value
    /// 6. return (power value,exp rows,mul rows,add rows)
    pub fn from_operands(base: U256, index: U256) -> (U256, Vec<Self>, Vec<arithmetic::Row>) {
        let base_hi = base >> 128;
        let base_lo: U256 = base.low_u128().into();
        let _index_hi = index >> 128;
        let _index_lo: U256 = index.low_u128().into();
        let mut exp_rows = vec![];
        let mut mul_row: Vec<arithmetic::Row> = vec![];

        let mut power_value = U256::one();
        let zero_row = Self {
            tag: Tag::Zero,
            base_hi,
            base_lo,
            index_hi: U256::zero(),
            index_lo: U256::zero(),
            count: U256::zero(),
            // is_high: U256::zero(),
            power_hi: U256::zero(),
            power_lo: U256::one(),
        };
        exp_rows.push(zero_row);
        if index.is_zero() {
            return (power_value, exp_rows, mul_row);
        }
        let one_row = Self {
            tag: Tag::One,
            base_hi,
            base_lo,
            index_hi: U256::zero(),
            index_lo: U256::one(),
            count: U256::zero(),
            // is_high: U256::zero(),
            power_hi: base_hi,
            power_lo: base_lo,
        };
        exp_rows.push(one_row);
        let mut div = index.clone();
        let mut rem = U256::zero();
        loop {
            // first generate bit0/1  row
            (div, rem) = div.div_mod(U256::from(2));
            // then generate bit0/1
            let pre_pre_id = exp_rows.len() - 2;
            let pre_id = exp_rows.len() - 1;
            let (bit_index_hi, bit_index_lo, bit_val) = if rem.is_zero() {
                // index = pre_pre_index
                // value = pre_pre_value
                (
                    exp_rows[pre_pre_id].index_hi,
                    exp_rows[pre_pre_id].index_lo,
                    (exp_rows[pre_pre_id].power_hi << 128).add(exp_rows[pre_pre_id].power_lo),
                )
            } else {
                // index hi = pre_pre_index hi + pre_index hi
                // index lo = pre_pre_index lo + pre_index lo
                // value = pre_pre_val * pre_val
                let pre_pre_index_hi = exp_rows[pre_pre_id].index_hi;
                let pre_pre_index_lo = exp_rows[pre_pre_id].index_lo;
                let pre_index_hi = exp_rows[pre_id].index_hi;
                let pre_index_lo = exp_rows[pre_id].index_lo;
                // generate mu pre_pre_val * pre_val
                let pre_pre_val =
                    (exp_rows[pre_pre_id].power_hi << 128).add(exp_rows[pre_pre_id].power_lo);
                let pre_val = (exp_rows[pre_id].power_hi << 128).add(exp_rows[pre_id].power_lo);
                let (pre_pre_val_mul_pre_val_rows, pre_pre_val_mul_pre_val_result) =
                    operation::mul::gen_witness(vec![pre_pre_val, pre_val]);
                mul_row.extend(pre_pre_val_mul_pre_val_rows);
                (
                    pre_pre_index_hi.add(pre_index_hi),
                    pre_pre_index_lo.add(pre_index_lo),
                    pre_pre_val_mul_pre_val_result[0],
                )
            };
            let bit_row = Self {
                tag: if rem.is_zero() { Tag::Bit0 } else { Tag::Bit1 },
                base_hi,
                base_lo,
                index_hi: bit_index_hi,
                index_lo: bit_index_lo,
                power_hi: bit_val >> 128,
                power_lo: bit_val.low_u128().into(),
                count: exp_rows.last().unwrap().count,
                // is_high: exp_rows.last().unwrap().is_high,
            };
            exp_rows.push(bit_row);
            if div.is_zero() {
                break;
            }
            // generate square row
            //use arithmetic mul
            // if pre_count + 1 = 128, index_hi = 1;index_lo = 0;
            //      else index_hi = pre_pre_index_hi * 2 ; index_lo = pre_pre_index_lo * 2;
            //pre_pre_index * 2
            let pre_pre_id = exp_rows.len() - 2;
            let pre_id = exp_rows.len() - 1;
            let pre_count = exp_rows[pre_id].count;
            // use arithmetic mul
            // pre_pre_power * pre_pre_power
            let pre_pre_val =
                (exp_rows[pre_pre_id].power_hi << 128).add(exp_rows[pre_pre_id].power_lo);
            let count = pre_count.add(U256::one());
            // let is_high = if count.is_zero() {
            //     U256::zero()
            // } else if count.eq(&U256::from(128)) {
            //     U256::one()
            // } else {
            //     exp_rows[pre_id].is_high
            // };
            let (index_hi, index_lo) = if count.eq(&U256::from(128)) {
                (U256::one(), U256::zero())
            } else {
                (
                    exp_rows[pre_pre_id].index_hi.mul(2),
                    exp_rows[pre_pre_id].index_lo.mul(2),
                )
            };
            // pre_pre_power * pre_pre_power
            let (val_mul_val_rows, val_mul_val_result) =
                operation::mul::gen_witness(vec![pre_pre_val, pre_pre_val]);
            mul_row.extend(val_mul_val_rows);
            // first generate square
            let square_row = Self {
                tag: Tag::Square,
                base_hi,
                base_lo,
                index_hi: index_hi,
                index_lo: index_lo,
                count,
                // is_high,
                power_hi: val_mul_val_result[0] >> 128,
                power_lo: val_mul_val_result[0].low_u128().into(),
            };
            exp_rows.push(square_row);
        }
        power_value =
            (exp_rows.last().unwrap().power_hi << 128).add(exp_rows.last().unwrap().power_lo);
        (power_value, exp_rows, mul_row)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        util::convert_u256_to_64_bytes,
        witness::{exp, Witness},
    };
    #[test]
    fn test_exp_normal() {
        for i in 0..10000 {
            let (c, _) = U256::from(3).overflowing_pow(U256::from(i));
            let (value, _exp, _) = exp::Row::from_operands(U256::from(3), U256::from(i));
            assert!(value.eq(&c))
        }
    }
    #[test]
    fn test_exp_overflow() {
        let index_mul = U256::MAX;
        let (c, _) = U256::from(3).overflowing_pow(index_mul.clone());
        println!("res: {:?}", c);
        println!("hex_res: {:?}", hex::encode(convert_u256_to_64_bytes(&c)));
        let (value, exp, mul) = exp::Row::from_operands(U256::from(3), index_mul);
        let mut buf = Vec::new();
        Witness::write_one_as_csv(&mut buf, &exp);
        Witness::write_one_as_csv(&mut buf, &mul);
        let csv_string = String::from_utf8(buf).unwrap();
        println!("{}", csv_string);
        println!(
            "hex_res: {:?}",
            hex::encode(convert_u256_to_64_bytes(&exp.last().unwrap().power_hi))
        );
        println!(
            "hex_res: {:?}",
            hex::encode(convert_u256_to_64_bytes(&exp.last().unwrap().power_lo))
        );
        assert!(value.eq(&c))
    }
}
