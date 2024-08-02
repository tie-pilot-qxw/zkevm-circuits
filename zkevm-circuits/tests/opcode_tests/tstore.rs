// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn tstore() {
    let key = U256::from_str_radix("0x23", 16).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        TSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
