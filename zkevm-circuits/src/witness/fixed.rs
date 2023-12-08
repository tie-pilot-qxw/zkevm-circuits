use eth_types::U256;
use serde::Serialize;
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    pub tag: Tag,
    pub value_0: Option<U256>,
    pub value_1: Option<U256>,
    pub value_2: Option<U256>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub enum Tag {
    #[default]
    And,
    Or,
    Xor,
    U16,
}
