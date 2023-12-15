use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn mstore_bytecode() {
    let offset: i32 = 1;
    let value = U256::from_str_radix(
        "0x00000000000000000000000000000000000000000000000000000000000000FF",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(value)
        PUSH1(offset)
        MSTORE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}