// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use eth_types::U256;
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// Tag could be ADD, MUL, ...
    pub tag: Tag,
    /// Counter for multi-row arithmetic operation, starts with positive number and decrements to 0
    pub cnt: U256,
    pub operand_0_hi: U256,
    pub operand_0_lo: U256,
    pub operand_1_hi: U256,
    pub operand_1_lo: U256,
    // 8 columns for u16 numbers
    pub u16_0: U256,
    pub u16_1: U256,
    pub u16_2: U256,
    pub u16_3: U256,
    pub u16_4: U256,
    pub u16_5: U256,
    pub u16_6: U256,
    pub u16_7: U256,
}

#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString, PartialEq)]
pub enum Tag {
    #[default]
    U64Overflow,
    Add,
    Sub,
    Mul,
    DivMod,
    SltSgt,
    SdivSmod,
    Addmod,
    Mulmod,
    Length,
    MemoryExpansion,
    U64Div,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}
