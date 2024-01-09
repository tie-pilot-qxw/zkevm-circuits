use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn log0_bytecode() {
    let bytecode = bytecode! {
        PUSH1(0)
        PUSH1(0)
        LOG0
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
