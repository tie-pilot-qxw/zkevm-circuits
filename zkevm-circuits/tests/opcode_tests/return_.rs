// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn return_bytecode() {
    let key: i32 = 0;
    let size: i32 = 2;
    let offset: i32 = 66;
    let value = U256::from_str_radix(
        "0xFF01000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(key)
        MSTORE
        PUSH1(size)
        PUSH1(offset)
        RETURN
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
