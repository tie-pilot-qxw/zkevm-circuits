// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::gen_random_neg_int_hex_str;
use crate::gen_random_pos_int_hex_str;
use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sdiv_bytecode_0() {
    let rstr1 = gen_random_pos_int_hex_str(64);
    let rstr2 = gen_random_pos_int_hex_str(64);
    let numerator = U256::from_str_radix(&rstr1, 16).unwrap();
    let denominator = U256::from_str_radix(&rstr2, 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(numerator)
        PUSH32(denominator)
        SDIV // numerator/denominator
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sdiv_bytecode_1() {
    let rstr1 = gen_random_neg_int_hex_str(64);
    let rstr2 = gen_random_pos_int_hex_str(64);
    let numerator = U256::from_str_radix(&rstr1, 16).unwrap();
    let denominator = U256::from_str_radix(&rstr2, 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(numerator)
        PUSH32(denominator)
        SDIV // numerator/denominator
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sdiv_bytecode_2() {
    let rstr1 = gen_random_pos_int_hex_str(64);
    let rstr2 = gen_random_neg_int_hex_str(64);
    let numerator = U256::from_str_radix(&rstr1, 16).unwrap();
    let denominator = U256::from_str_radix(&rstr2, 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(numerator)
        PUSH32(denominator)
        SDIV // numerator/denominator
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sdiv_bytecode_3() {
    let rstr1 = gen_random_neg_int_hex_str(64);
    let rstr2 = gen_random_neg_int_hex_str(64);
    let numerator = U256::from_str_radix(&rstr1, 16).unwrap();
    let denominator = U256::from_str_radix(&rstr2, 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(numerator)
        PUSH32(denominator)
        SDIV // numerator/denominator
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
