// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::{gen_random_hex_str, test_super_circuit_short_bytecode};
use eth_types::{bytecode, U256};

#[test]
fn balance_bytecode() {
    let address = U256::from_str_radix(&gen_random_hex_str(20), 16).unwrap();
    let bytecode = bytecode! {
        PUSH20(address)
        BALANCE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn balance_with_address_warm() {
    let address = U256::from_str_radix(&gen_random_hex_str(20), 16).unwrap();
    let bytecode = bytecode! {
        PUSH20(address)
        BALANCE
        PUSH20(address)
        BALANCE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
