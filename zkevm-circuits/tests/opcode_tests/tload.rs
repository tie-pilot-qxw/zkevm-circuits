// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn tload_normal() {
    let key = U256::from_str_radix("1", 10).unwrap();
    let value = U256::from_str_radix("46", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        TSTORE
        PUSH1(key)
        TLOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn tload_not_exist_key01() {
    let key = U256::from_str_radix("1", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(key)
        TLOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn tload_not_exist_key02() {
    let key = U256::from_str_radix("1", 10).unwrap();
    let value = U256::from_str_radix("46", 10).unwrap();
    let key_not_exist = U256::from_str_radix("0", 10).unwrap();
    let other_value = U256::from_str_radix("3", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        TSTORE
        PUSH1(key)
        TLOAD
        PUSH1(key_not_exist)
        TLOAD
        PUSH1(other_value)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
