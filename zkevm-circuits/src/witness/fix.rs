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

#[cfg(test)]
mod test {
    use crate::witness::fix::{Row, Tag};
    #[test]
    fn print_csv() {
        let row0 = Row {
            tag: Tag::And,
            value_0: Some(0.into()),
            value_1: Some(0.into()),
            value_2: Some(0.into()),
        };

        let row1 = Row {
            tag: Tag::Or,
            value_0: Some(0.into()),
            value_1: Some(0.into()),
            value_2: Some(0.into()),
        };

        let row2 = Row {
            tag: Tag::Xor,
            value_0: Some(0.into()),
            value_1: Some(0.into()),
            value_2: Some(0.into()),
        };

        let row3 = Row {
            tag: Tag::U16,
            value_0: Some(0.into()),
            value_1: Some(0.into()),
            value_2: Some(0.into()),
        };
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        wtr.serialize(&row0).unwrap();
        wtr.serialize(&row1).unwrap();
        wtr.serialize(&row2).unwrap();
        wtr.serialize(&row3).unwrap();
        wtr.flush().unwrap();
    }
}
