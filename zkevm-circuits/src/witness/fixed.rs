// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use eth_types::U256;
use serde::Serialize;

pub const U10_TAG: usize = 1024;

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
    U16,
    // Make sure this equals bitwise Row's And
    And,
    // Make sure this equals bitwise Row's tag
    Or,
    // The tag for (Opcode,PUSH number,PUSH number>15)
    Bytecode,
    // Opcode for non-zero constant gas consumption
    ConstantGasCost,
}
