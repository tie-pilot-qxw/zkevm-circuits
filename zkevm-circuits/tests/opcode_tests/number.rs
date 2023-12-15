use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn number_bytecode() {
    let bytecode = bytecode! {
        NUMBER
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}