// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn swap7_bytecode() {
    let bytecode = bytecode! {
        PUSH1(2)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(1)
        SWAP7
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
