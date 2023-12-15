use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mstore8_bytecode() {
    let offset: i32 = 1;
    let value = U256::from_str_radix(
        "0xFFFF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH2(value)
        PUSH1(offset)
        MSTORE8
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}