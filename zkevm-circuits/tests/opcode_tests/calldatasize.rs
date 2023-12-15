use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn calldatasize_bytecode() {
    let bytecode = bytecode! {
        CALLDATASIZE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}