use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn lt0_bytecode() {
    let a = U256::from_str_radix("9", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        LT // a<b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a<b

#[test]
fn lt1_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("9", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        LT // a<b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a>b

#[test]
fn lt2_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        LT // a<b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a=b
