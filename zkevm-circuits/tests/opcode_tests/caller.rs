use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn caller_bytecode() {
    let bytecode = bytecode! {
        CALLER
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
