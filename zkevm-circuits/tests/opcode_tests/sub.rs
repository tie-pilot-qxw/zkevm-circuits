use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sub_bytecode() {
    let a = U256::from_str_radix("0", 10).unwrap();
    let b = U256::from_str_radix("1", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        SUB //a-b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // sub with overflow

#[test]
fn sub_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        SUB //a-b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // sub without overflow
