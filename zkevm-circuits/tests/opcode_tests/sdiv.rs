use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sdiv_bytecode() {
    let a = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH32(a)
        SDIV // a/b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // signed integer division with remainder

#[test]
fn sdiv_without_remainder_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        SDIV // a/b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // signed integer division without reminder
