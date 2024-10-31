// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use eth_types::U256;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// the contract address of the bytecodes
    pub addr: Option<U256>,
    /// the index that program counter points to
    pub pc: Option<U256>,
    /// bytecode, operation code or pushed value
    pub bytecode: Option<U256>,
    /// pushed value, high 128 bits (0 or non-push opcodes)
    pub value_hi: Option<U256>,
    /// pushed value, low 128 bits (0 or non-push opcodes)
    pub value_lo: Option<U256>,
    /// accumulated value, high 128 bits. accumulation will go X times for PUSHX
    pub acc_hi: Option<U256>,
    /// accumulated value, low 128 bits. accumulation will go X times for PUSHX
    pub acc_lo: Option<U256>,
    /// count for accumulation, accumulation will go X times for PUSHX
    pub cnt: Option<U256>,
    /// whether count is equal or larger than 16
    pub is_high: Option<U256>,
    /// poseidon hash, maximum 254 bits
    pub hash: Option<U256>,
    /// the effective length of the contract bytecode
    pub length: Option<U256>,
    /// whether the current bytecode is a padding bytecode
    /// padding is only done at the end of the bytecode to handle the case where the number of bytes pushed by the pushX instruction is less than X.
    pub is_padding: Option<U256>,
}
