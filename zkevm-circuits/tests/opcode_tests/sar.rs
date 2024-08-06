// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sar_normal_bytecode() {
    let shift = U256::one();
    let value = U256::from_str_radix("2", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(shift)
        SAR
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sar_neg_bytecode() {
    let value = U256::from_str_radix(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
        16,
    )
    .unwrap();
    let shift = U256::from(4);
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(shift)
        SAR
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sar_shift_0_bytecode() {
    let value = U256::from_str_radix(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
        16,
    )
    .unwrap();
    let shift = U256::from(0);
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(shift)
        SAR
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sar_shift_gt_255_bytecode() {
    let value = U256::from_str_radix(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
        16,
    )
    .unwrap();
    let shift = U256::from(257);
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH2(shift)
        SAR
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
