use crate::util::{convert_f_to_u256, convert_u256_to_f};
use crate::witness::bitwise;
use eth_types::{Field, U256};
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// The operation tag, one of AND, OR, XOR
    pub tag: Tag,
    /// The byte value of operand 0
    pub byte_0: U256,
    /// The byte value of operand 1
    pub byte_1: U256,
    /// The byte value of operand 2
    pub byte_2: U256,
    /// The accumulation of bytes in one operation of operand 0
    pub acc_0: U256,
    /// The accumulation of bytes in one operation of operand 1
    pub acc_1: U256,
    /// The accumulation of bytes in one operation of operand 2
    pub acc_2: U256,
    /// The sum of bytes in one operation of operand 2, used to compute byte opcode
    pub sum_2: U256,
    /// The counter for one operation
    pub cnt: U256,
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    #[default]
    Nil,
    And,
    Or,
    Xor,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

// return bitwise rows
pub fn get_bitwise_row<F: Field>(
    tag: bitwise::Tag,
    operand1: u128,
    operand2: u128,
) -> Vec<bitwise::Row> {
    let operand1_bytes: [u8; 16] = operand1.to_be_bytes();
    let operand2_bytes: [u8; 16] = operand2.to_be_bytes();
    get_bitwise_row_by_u8_bytes::<F>(tag, operand1_bytes, operand2_bytes)
}

pub fn get_bitwise_row_by_u8_bytes<F: Field>(
    tag: bitwise::Tag,
    operand1_bytes: [u8; 16],
    operand2_bytes: [u8; 16],
) -> Vec<bitwise::Row> {
    let mut row_vec: Vec<bitwise::Row> = vec![];

    // begin padding
    let mut byte_acc_pre_vec = vec![U256::from(0), U256::from(0), U256::from(0)];
    let mut byte_2_sum_pre = U256::from(0);
    let temp_256_f = F::from(256);
    for i in 0..16 {
        let mut byte_vec = vec![U256::from(operand1_bytes[i]), U256::from(operand2_bytes[i])];
        // calc byte_2
        match tag {
            bitwise::Tag::Nil => byte_vec.push(U256::from(0)),
            bitwise::Tag::And => byte_vec.push(U256::from(operand1_bytes[i] & operand2_bytes[i])),
            bitwise::Tag::Or => byte_vec.push(U256::from(operand1_bytes[i] | operand2_bytes[i])),
            bitwise::Tag::Xor => byte_vec.push(U256::from(operand1_bytes[i] ^ operand2_bytes[i])),
        }

        let mut byte_acc_vec: Vec<U256> = vec![];
        let mut byte_2_sum = U256::from(0);

        for i in 0..3 {
            let mut acc_f = convert_u256_to_f::<F>(&byte_acc_pre_vec[i]);
            let byte_f = convert_u256_to_f::<F>(&byte_vec[i]);
            acc_f = byte_f + acc_f * temp_256_f;
            byte_acc_vec.push(convert_f_to_u256(&acc_f));
            byte_acc_pre_vec[i] = byte_acc_vec[i];

            // calc byte_2_sum
            if i == 2 {
                let mut byte_2_sum_f = convert_u256_to_f::<F>(&byte_2_sum_pre);
                byte_2_sum_f = byte_f + byte_2_sum_f;
                byte_2_sum = convert_f_to_u256(&byte_2_sum_f);
                byte_2_sum_pre = byte_2_sum;
            }
        }

        let row = Row {
            tag,
            byte_0: byte_vec[0],
            byte_1: byte_vec[1],
            byte_2: byte_vec[2],
            acc_0: byte_acc_vec[0],
            acc_1: byte_acc_vec[1],
            acc_2: byte_acc_vec[2],
            sum_2: byte_2_sum,
            cnt: U256::from(i),
        };
        row_vec.push(row)
    }
    row_vec
}
