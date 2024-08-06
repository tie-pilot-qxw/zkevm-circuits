// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mload_bytecode() {
    let offset_store: i32 = 128;
    let offset_load: i32 = 1;
    let value = U256::from_str_radix(
        "0x00000000000000000000000000000000000000000000000000000000000000FF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(offset_store)
        MSTORE
        PUSH1(offset_load)
        MLOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn mload_bytecode_1() {
    let offset_store: i32 = 0;
    let offset_load: i32 = 0;
    let value = U256::from_str_radix(
        "0x00000000000000000000000000000000000000000000000000000000000000FF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(offset_store)
        MSTORE
        PUSH1(offset_load)
        MLOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
