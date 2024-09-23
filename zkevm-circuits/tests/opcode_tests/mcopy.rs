// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mcopy_bytecode() {
    let value = U256::from_str_radix(
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(32)
        MSTORE
        PUSH1(32)
        PUSH1(32)
        PUSH1(0)
        MCOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
