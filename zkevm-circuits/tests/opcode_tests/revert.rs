// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn revert_bytecode() {
    let _key: i32 = 0;
    let size: i32 = 2;
    let offset: i32 = 0;
    let _value = U256::from_str_radix(
        "0xFF01000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH1(size)
        PUSH1(offset)
        REVERT
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn revert_bytecode_expansion() {
    let _key: i32 = 0;
    let size: i32 = 2;
    let offset: i32 = 0;
    let value = U256::from_str_radix(
        "0xFF01000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(0)
        MSTORE
        PUSH1(size)
        PUSH1(offset)
        REVERT
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
