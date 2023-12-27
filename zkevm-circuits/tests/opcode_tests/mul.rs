use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mul_bytecode() {
    let a = U256::from_str_radix("2", 10).unwrap();
    let b = U256::max_value();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH1(a)
        MUL // a*b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multiplication with overflow

#[test]
fn mul_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        MUL // a*b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multiplication without overflow
