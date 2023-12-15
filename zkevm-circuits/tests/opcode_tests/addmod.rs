use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn addmod_bytecode() {
    let a = U256::max_value();
    let b = U256::from_str_radix("2", 10).unwrap();
    let n: U256 = U256::from_str_radix("2", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH1(b)
        PUSH32(a)
        ADDMOD // (a+b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer addition (with overflow) then modulo

#[test]
fn addmod_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let n = U256::from_str_radix("8", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH1(b)
        PUSH1(a)
        ADDMOD // (a+b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer addition (without overflow) then modulo
