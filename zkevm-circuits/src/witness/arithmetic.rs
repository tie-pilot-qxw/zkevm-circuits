use eth_types::U256;
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// Tag could be ADD, MUL, ...
    pub tag: Option<Tag>,
    /// Counter for multi-row arithmetic operation, starts with positive number and decrements to 0
    pub cnt: Option<U256>,
    pub operand0_hi: Option<U256>,
    pub operand0_lo: Option<U256>,
    pub operand1_hi: Option<U256>,
    pub operand1_lo: Option<U256>,
    pub operand2_hi: Option<U256>,
    pub operand2_lo: Option<U256>,
    pub operand3_hi: Option<U256>,
    pub operand3_lo: Option<U256>,
    // 8 columns for u16 numbers
    pub u16_0: Option<U256>,
    pub u16_1: Option<U256>,
    pub u16_2: Option<U256>,
    pub u16_3: Option<U256>,
    pub u16_4: Option<U256>,
    pub u16_5: Option<U256>,
    pub u16_6: Option<U256>,
    pub u16_7: Option<U256>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    #[default]
    Nil,
    Add,
    Addmod,
    Mul,
    Lt,
    Gt,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

#[cfg(test)]
mod test {
    use crate::witness::arithmetic::{Row, Tag};

    #[test]
    fn print_csv() {
        let row0 = Row {
            cnt: Some(1.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        let row1 = Row {
            tag: Some(Tag::Add),
            cnt: Some(0.into()),
            operand0_hi: Some(0.into()),
            operand0_lo: Some(0.into()),
            operand1_hi: Some(0.into()),
            operand1_lo: Some(0.into()),
            operand2_hi: Some(0.into()),
            operand2_lo: Some(0.into()),
            operand3_hi: Some(0.into()),
            operand3_lo: Some(0.into()),
            u16_0: Some(0.into()),
            u16_1: Some(0.into()),
            u16_2: Some(0.into()),
            u16_3: Some(0.into()),
            u16_4: Some(0.into()),
            u16_5: Some(0.into()),
            u16_6: Some(0.into()),
            u16_7: Some(0.into()),
            ..Default::default()
        };
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        wtr.serialize(&row0).unwrap();
        wtr.serialize(&row1).unwrap();
        wtr.flush().unwrap();
    }
}
