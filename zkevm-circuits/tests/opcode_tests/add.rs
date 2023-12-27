use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn add_bytecode() {
    let a = U256::from_str_radix(
        "0xff03210321032103210303210321032103210321032103210321032103210321",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xff10321032103210321032103210321032103210321032103210321032103210",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH32(a)
        ADD //a+b
        STOP
    }; //add with overflow
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn add_without_overflow_bytecode() {
    let a = U256::from_str_radix("10", 10).unwrap();
    let b = U256::from_str_radix("10", 10).unwrap();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH32(a)
        ADD //a+b
        STOP
    }; //add without overflow
    test_super_circuit_short_bytecode!(bytecode);
}
