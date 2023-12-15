use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn shr0_bytecode() {
    let shift = U256::from_str_radix("4", 10).unwrap();
    let value = U256::from_str_radix("0xFF", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(shift)
        SHR // value>>shift
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn shr1_bytecode() {
    let shift = U256::from_str_radix("1", 10).unwrap();
    let value = U256::from_str_radix("2", 10).unwrap();
    let bytecode = bytecode! {
        PUSH1(value)
        PUSH1(shift)
        SHR // value>>shift
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
