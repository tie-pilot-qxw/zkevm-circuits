use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    // type of row, one of zero, one, base2 or arbitrary
    pub tag: Tag,
    // base of exp
    pub base_hi: U256,
    pub base_lo: U256,
    // index of exp
    pub index_hi: U256,
    pub index_lo: U256,
    // count of index
    pub count: Option<U256>,
    // whether count is equal or large than 2**128
    pub is_high: U256,
    // exp res
    pub power_hi: U256,
    pub power_lo: U256,
}

#[derive(Clone, Debug, Default, Serialize)]
pub enum Tag {
    #[default]
    Zero,
    One,
    Base2,
    Arbitrary,
}

impl Row {
    pub fn from_operands(base: U256, index: U256, power: U256) -> Vec<Self> {
        vec![Row {
            base_hi: base >> 128,
            base_lo: base.low_u128().into(),
            index_hi: index >> 128,
            index_lo: index.low_u128().into(),
            power_hi: power >> 128,
            power_lo: power.low_u128().into(),
            ..Default::default()
        }]
    }
}
