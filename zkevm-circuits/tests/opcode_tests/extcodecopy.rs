use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn extcodecopy_bytecode() {
    let value1 = U256::from_str_radix(
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let value2 = U256::from_str_radix(
        "0xFF60005260206000F30000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        // Creates a constructor that creates a contract with 32 FF as code
        PUSH32(value1)
        PUSH1(0)
        MSTORE
        PUSH32(value2)
        PUSH1(32)
        MSTORE

        // Create the contract with the constructor code above
        PUSH1(41)
        PUSH1(0)
        PUSH1(0)
        CREATE // Puts the new contract address on the stack

        // Clear the memory for the examples
        PUSH1 (0)
        PUSH1 (0)
        MSTORE
        PUSH1 (0)
        PUSH1 (32)
        MSTORE

        // Example 1
        PUSH1 (32)
        PUSH1 (0)
        PUSH1 (0)
        DUP4
        EXTCODECOPY

        // Example 2
        PUSH1 (8)
        PUSH1 (31)
        PUSH1 (0)
        DUP4
        EXTCODECOPY

        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
