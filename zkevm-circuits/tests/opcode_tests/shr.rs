// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn shr_bytecode() {
    let value = U256::from_str_radix("0x553e92e8bc0ae9a795ed1f57f3632d4d", 16).unwrap();
    for shift in [0, 1, 31, 32, 255, 256] {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(shift)
            SHR // value>>shift
            STOP
        };
        test_super_circuit_short_bytecode!(bytecode);
    }
}
