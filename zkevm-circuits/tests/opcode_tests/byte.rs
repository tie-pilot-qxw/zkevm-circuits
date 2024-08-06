// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn byte_bytecode() {
    let a = U256::from_str_radix(
        "0x9F3A9ED44CC365B380A6BCF56590777A1C20CE55FE82D8D833B57B3AA2512F86",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix("31", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH32(a)
        BYTE // b-th byte of a
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
