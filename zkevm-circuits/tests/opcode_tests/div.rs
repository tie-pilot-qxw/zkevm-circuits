use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn div_bytecode() {
    let a = U256::from_str_radix("1", 10).unwrap();
    let b = U256::from_str_radix("2", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        DIV // a/b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // div with remainder

#[test]
fn div_without_remainder_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        DIV // a/b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // div without reminder
