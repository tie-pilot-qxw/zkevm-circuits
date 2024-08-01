use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn push0_bytecode() {
    let bytecode = bytecode! {
        PUSH0
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
