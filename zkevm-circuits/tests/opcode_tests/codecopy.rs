// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn codecopy_bytecode() {
    let dest_offset: i32 = 1;
    let offset: i32 = 31;
    let size: i32 = 8;
    let bytecode = bytecode! {
        PUSH1(size)
        PUSH1(offset)
        PUSH1(dest_offset)
        CODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn codecopy_bytecode_1() {
    let dest_offset: i32 = 0;
    let offset: i32 = 0;
    let size: i32 = 0;
    let bytecode = bytecode! {
        PUSH1(size)
        PUSH1(offset)
        PUSH1(dest_offset)
        CODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
