// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::ops::Add;

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn exp_bytecode() {
    let r = u128::max_value().to_string();
    let a = U256::from_str_radix(&r, 10).unwrap().add(0);
    let b = U256::from_str_radix("2", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH32(a)
        EXP // a^b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer exponential with overflow

#[test]
fn exp_without_overflow_bytecode() {
    let a = U256::from_str_radix("2", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        EXP // a^b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer exponential without overflow

#[test]
fn exp_index_is_zero() {
    let a = U256::from_str_radix("2", 10).unwrap();
    let b = U256::from_str_radix("0", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        EXP // a^b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer exponential without overflow
