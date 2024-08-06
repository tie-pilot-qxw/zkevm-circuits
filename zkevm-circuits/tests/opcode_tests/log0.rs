// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn log0_bytecode() {
    let size = 32;
    let offset = 0;

    let bytecode = bytecode! {
        PUSH32(size)
        PUSH32(offset)
        LOG0
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
