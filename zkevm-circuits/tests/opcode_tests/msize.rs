use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn msize_bytecode() {
    let value = U256::from_str_radix(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let value2 = U256::from_str_radix(
        "0x0000000000000000000000000000000000000000000000000000000000000039",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        MSIZE // Initially 0
        PUSH1(value)
        MLOAD // Read first word
        POP
        MSIZE // Now size is 1 word
        PUSH1(value2)
        MLOAD // Read part of third word
        POP
        MSIZE
        MSIZE // Now size is 3 words
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn msize_bytecode_len_0() {
    let bytecode = bytecode! {
        MSIZE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
