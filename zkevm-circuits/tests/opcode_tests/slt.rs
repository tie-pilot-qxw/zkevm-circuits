use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn slt0_bytecode() {
    let a = U256::max_value();
    let b = U256::from_str_radix("9", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH32(a)
        SLT // a<b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a<b

#[test]
fn slt1_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::max_value();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH1(a)
        SLT // a>b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a>b

#[test]
fn slt2_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(b)
        PUSH1(a)
        SLT // a>b : 1 if a is smaller, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a=b
