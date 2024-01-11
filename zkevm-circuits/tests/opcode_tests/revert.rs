use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn revert_bytecode() {
    let _key: i32 = 0;
    let size: i32 = 2;
    let offset: i32 = 0;
    let _value = U256::from_str_radix(
        "0xFF01000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH1(size)
        PUSH1(offset)
        REVERT
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
