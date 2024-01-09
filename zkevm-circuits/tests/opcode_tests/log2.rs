use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn log2_bytecode() {
    let bytecode = bytecode! {
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        LOG2
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
