// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mulmod_bytecode() {
    let a = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let n = U256::from_str_radix("12", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH32(b)
        PUSH32(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multiplication (with overflow) then modulo

#[test]
fn mulmod_bytecode_n_is_0() {
    let a = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let n = U256::from_str_radix("0", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH32(b)
        PUSH32(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multiplication (with overflow) then modulo

#[test]
fn mulmod_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let n = U256::from_str_radix("8", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH1(b)
        PUSH1(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multplication (without overflow) then modulo

#[test]
fn mulmod_without_overflow_bytecode_n_is_0() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let n = U256::from_str_radix("0", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH1(b)
        PUSH1(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
