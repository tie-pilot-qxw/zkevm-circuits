use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mulmod_bytecode() {
    let a = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let n = U256::from_str_radix("12", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH32(b)
        PUSH32(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multiplication (with overflow) then modulo

#[test]
fn mulmod_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let n = U256::from_str_radix("8", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(n)
        PUSH1(b)
        PUSH1(a)
        MULMOD // (a*b) mod n
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
} // integer multplication (without overflow) then modulo
