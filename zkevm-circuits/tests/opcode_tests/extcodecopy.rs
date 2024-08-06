// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn test_copy_normal() {
    // default address
    let address = U256::from_str_radix("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 16).unwrap();
    let value = U256::from_str_radix(
        "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        // Example 1
        PUSH1(32)  // size
        PUSH1(1)  // offset
        PUSH1(0)  // dstOffset
        PUSH20(address)
        EXTCODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
// exceeds the size of the finite field F
// final acc: fdffff1fd8143c78dd1e8dc6f2f98af454ffdfc92745f8facbf9c3d1a63371f
#[test]
fn test_copy_exceeds_f() {
    // default address
    let address = U256::from_str_radix("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 16).unwrap();
    let value = U256::from_str_radix(
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        // Example 1
        PUSH1(32)  // size
        PUSH1(1)  // offset
        PUSH1(0)  // dest offset
        PUSH20(address)
        EXTCODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn test_copy_addr_not_exist() {
    // default address
    let address = U256::from_str_radix("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb", 16).unwrap();
    let value = U256::from_str_radix(
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        // Example 1
        PUSH1(32)  // size
        PUSH1(1)  // offset
        PUSH1(0)  // dest offset
        PUSH20(address)
        EXTCODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn test_copy_all_zero() {
    // default address
    let address = U256::from_str_radix("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 16).unwrap();
    let bytecode = bytecode! {
        // Example 1
        PUSH1(0)  // size
        PUSH1(0)  // offset
        PUSH1(0)  // dest offset
        PUSH20(address)
        EXTCODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

// CRATE not implemented
// #[test]
// fn extcodecopy_bytecode() {
//     let value1 = U256::from_str_radix(
//         "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
//         16,
//     )
//     .unwrap();
//     let value2 = U256::from_str_radix(
//         "0xFF60005260206000F30000000000000000000000000000000000000000000000",
//         16,
//     )
//     .unwrap();
//     let bytecode = bytecode! {
//         // Creates a constructor that creates a contract with 32 FF as code
//         PUSH32(value1)
//         PUSH1(0)
//         MSTORE
//         PUSH32(value2)
//         PUSH1(32)
//         MSTORE
//
//         // Create the contract with the constructor code above
//         PUSH1(41)
//         PUSH1(0)
//         PUSH1(0)
//         CREATE // Puts the new contract address on the stack
//
//         // Clear the memory for the examples
//         PUSH1 (0)
//         PUSH1 (0)
//         MSTORE
//         PUSH1 (0)
//         PUSH1 (32)
//         MSTORE
//
//         // Example 1
//         PUSH1 (32)
//         PUSH1 (0)
//         PUSH1 (0)
//         DUP4
//         EXTCODECOPY
//
//         // Example 2
//         PUSH1 (8)
//         PUSH1 (31)
//         PUSH1 (0)
//         DUP4
//         EXTCODECOPY
//
//         STOP
//     };
//     test_super_circuit_short_bytecode!(bytecode);
// }
