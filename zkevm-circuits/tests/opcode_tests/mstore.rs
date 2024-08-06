// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mstore_bytecode() {
    let offset: i32 = 1;
    let value = U256::from_str_radix(
        "0x00000000000000000000000000000000000000000000000000000000000000FF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(offset)
        MSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn mstore_bytecode_1() {
    let offset_0: i32 = 0;
    let offset_1: i32 = 1;
    let value_ff = U256::from_str_radix(
        "0x00000000000000000000000000000000000000000000000000000000000000FF",
        16,
    )
    .unwrap();

    let bytecode = bytecode! {
    // Put the state in memory
    PUSH32(value_ff)
    PUSH1(offset_0)
    MSTORE

    // Example 1
    PUSH1(offset_0)
    MLOAD

    // Example 2
    PUSH1(offset_1)
    MLOAD
    STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
