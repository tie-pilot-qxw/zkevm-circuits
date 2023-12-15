use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn calldataload_bytecode() {
    let bytecode = bytecode! {
        PUSH1(31)
        CALLDATALOAD
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
