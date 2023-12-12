use eth_types::U256;
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
