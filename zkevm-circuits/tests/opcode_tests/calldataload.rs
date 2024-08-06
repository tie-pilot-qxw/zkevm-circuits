// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn calldataload_bytecode_0() {
    // value = 2^128 - 1
    let i2_128_min_1 = U256::from_str_radix("0xffffffffffffffffffffffffffffffff", 16).unwrap();
    let value = i2_128_min_1;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_1() {
    // value = 2^128
    let i2_128_min_1 = U256::from_str_radix("0xffffffffffffffffffffffffffffffff", 16).unwrap();
    let (i2_128, _) = U256::overflowing_add(i2_128_min_1, U256::one());
    let value = i2_128;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_2() {
    // value = 2^64 - 1
    let i2_64_min_1 = U256::from_str_radix("0xffffffffffffffff", 16).unwrap();
    let value = i2_64_min_1;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_3() {
    // value = 2^64
    let i2_64_min_1 = U256::from_str_radix("0xffffffffffffffff", 16).unwrap();
    let (i2_64, _) = U256::overflowing_add(i2_64_min_1, U256::one());
    let value = i2_64;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_4() {
    // value = 2^64 - 32
    let i2_64_min_1 = U256::from_str_radix("0xffffffffffffffff", 16).unwrap();
    let i32 = U256::from_str_radix("32", 10).unwrap();
    let (i2_64, _) = U256::overflowing_add(i2_64_min_1, U256::one());
    let (i2_64_min_32, _) = U256::overflowing_sub(i2_64, i32);
    let value = i2_64_min_32;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_5() {
    // value = 2^64 - 31
    let i2_64_min_1 = U256::from_str_radix("0xffffffffffffffff", 16).unwrap();
    let i31 = U256::from_str_radix("31", 10).unwrap();
    let (i2_64, _) = U256::overflowing_add(i2_64_min_1, U256::one());
    let (i2_64_min_31, _) = U256::overflowing_sub(i2_64, i31);
    let value = i2_64_min_31;

    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}

#[test]
fn calldataload_bytecode_6() {
    // value = 2^256 - 1
    let value = U256::from_str_radix(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}
