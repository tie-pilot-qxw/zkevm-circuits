// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sha3_bytecode() {
    let a = U256::from_str_radix("0x0", 16).unwrap();
    let b = U256::from_str_radix("0x4", 16).unwrap();
    let bytecode = bytecode! {
        PUSH32(a)
        PUSH32(b)
        SHA3
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
