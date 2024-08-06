// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mod_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("3", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        MOD //a%b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer modulo
