// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::gen_random_hex_str;
use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn log1_bytecode() {
    let size = 32;
    let offset = 0;
    let topic1 = U256::from_str_radix(&gen_random_hex_str(64), 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(topic1)
        PUSH32(size)
        PUSH32(offset)
        LOG1
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
