use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode};

#[test]
fn blockhash_bytecode() {
    let bytecode = bytecode! {
        PUSH32(0)
        BLOCKHASH
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}