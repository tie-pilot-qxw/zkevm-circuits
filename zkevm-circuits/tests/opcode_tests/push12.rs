// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::gen_random_hex_str;
use crate::get_func_name;
use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn push12_bytecode() {
    let func_name = get_func_name!().to_string();
    let my_vec: Vec<char> = func_name.chars().collect();
    let num_byte = usize::try_from(my_vec[4].to_digit(10).unwrap()).unwrap();
    let str1 = gen_random_hex_str(num_byte * 2);
    let str2 = gen_random_hex_str(num_byte * 2);

    let first = U256::from_str_radix(&str1, 16).unwrap();
    let second = U256::from_str_radix(&str2, 16).unwrap();
    let bytecode = bytecode! {
        PUSH12(first)
        PUSH12(second)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
