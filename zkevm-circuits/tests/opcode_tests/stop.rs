use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn stop_bytecode() {
    let bytecode = bytecode! {
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
