use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sload_bytecode() {
    let key_store = U256::from_str_radix("0", 10).unwrap();
    let key_load = U256::from_str_radix("1", 10).unwrap();
    let value = U256::from_str_radix("46", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key_store)
        SSTORE
        PUSH1(key_load)
        SLOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}