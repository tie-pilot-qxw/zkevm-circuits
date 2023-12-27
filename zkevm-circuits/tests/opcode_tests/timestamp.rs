use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn timestamp_bytecode() {
    let bytecode = bytecode! {
        TIMESTAMP
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
