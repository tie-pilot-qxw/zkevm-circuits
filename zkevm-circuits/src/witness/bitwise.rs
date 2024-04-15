use crate::util::{convert_f_to_u256, convert_u256_to_f};
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
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

impl Row {
    // return bitwise rows for one operation and a pair of operands
    pub fn from_operation<F: Field>(tag: Tag, operand1: u128, operand2: u128) -> Vec<Row> {
        let operand1_bytes: [u8; 16] = operand1.to_be_bytes();
        let operand2_bytes: [u8; 16] = operand2.to_be_bytes();
        Self::from_operation_bytes::<F>(tag, operand1_bytes, operand2_bytes)
    }

    fn from_operation_bytes<F: Field>(
        tag: Tag,
        operand1_bytes: [u8; 16],
        operand2_bytes: [u8; 16],
    ) -> Vec<Row> {
        let mut row_vec: Vec<Row> = vec![];

        // begin padding
        let mut byte_acc_pre_vec = vec![U256::zero(), U256::zero(), U256::zero()];
        let mut byte_2_sum_pre = U256::zero();
        let temp_256_f = F::from(256);
        for i in 0..16 {
            let mut byte_vec = vec![operand1_bytes[i].into(), operand2_bytes[i].into()];
            // calc byte_2
            match tag {
                Tag::Nil => byte_vec.push(U256::zero()),
                Tag::And => byte_vec.push((operand1_bytes[i] & operand2_bytes[i]).into()),
                Tag::Or => byte_vec.push((operand1_bytes[i] | operand2_bytes[i]).into()),
            }

            let mut byte_acc_vec: Vec<U256> = vec![];
            let mut byte_2_sum = U256::zero();

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
                cnt: i.into(),
            };
            row_vec.push(row)
        }
        row_vec
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::witness::Witness;
    use halo2_proofs::halo2curves::bn256::Fr;
    #[test]
    fn test_get_bitwise_row() {
        let operand1 = U256::from_little_endian(&[0xabu8, 0xcdu8, 0xefu8]);
        let operand2 = U256::from_little_endian(&[0xaau8, 0xbbu8, 0xccu8]);

        let operand1_hi = (operand1 >> 128).as_u128();
        let operand1_lo = operand1.low_u128();

        let operand2_hi = (operand2 >> 128).as_u128();
        let operand2_lo = operand2.low_u128();
        let mut bitwise = vec![];
        bitwise.append(&mut Row::from_operation::<Fr>(
            Tag::And,
            operand1_lo,
            operand2_lo,
        ));
        bitwise.append(&mut Row::from_operation::<Fr>(
            Tag::And,
            operand1_hi,
            operand2_hi,
        ));
        let mut buf = Vec::new();
        Witness::write_one_as_csv(&mut buf, &bitwise);
        let csv_string = String::from_utf8(buf).unwrap();
        println!("{}", csv_string);
    }
}
