use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn iszero1_bytecode() {
    let a = U256::from_str_radix("0", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(a)
        ISZERO // a?=0 : 1 if a=0, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a=0

#[test]
fn iszero0_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(a)
        ISZERO // a?=0 : 1 if a=0, 0 otherwise
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // a!=0
