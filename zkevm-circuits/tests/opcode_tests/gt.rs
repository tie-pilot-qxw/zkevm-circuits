// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn gt0_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("9", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        GT // a>b : 1 if a is bigger, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a>b

#[test]
fn gt1_bytecode() {
    let a = U256::from_str_radix("9", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        GT // a>b : 1 if a is bigger, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a<b

#[test]
fn gt2_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        GT // a>b : 1 if a is bigger, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a=b
