use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn sstore_bytecode() {
    let key = U256::from_str_radix("0", 10).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(key)
        SSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
