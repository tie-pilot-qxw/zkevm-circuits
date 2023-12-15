use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn selfbalance_bytecode() {
    let bytecode = bytecode! {
        SELFBALANCE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}