use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sstore_bytecode() {
    let key = U256::from_str_radix("0x23", 16).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        SSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sstore_bytecode_is_warm() {
    let key = U256::from_str_radix("0x23", 16).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let value_2 = U256::from_str_radix("0x01", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        SSTORE
        PUSH1(value_2)
        PUSH1(key)
        SSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn sstore_bytecode_has_refund() {
    let key = U256::from_str_radix("0x23", 16).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let value_2 = U256::from_str_radix("0x0", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        SSTORE
        PUSH1(value_2)
        PUSH1(key)
        SSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
