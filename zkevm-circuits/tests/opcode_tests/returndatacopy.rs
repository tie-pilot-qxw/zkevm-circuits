use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn returndatacopy_bytecode() {
    let bytecode = bytecode! {
        PUSH1(32)
        PUSH1(0)
        PUSH1(0)
        RETURNDATACOPY
    };
    test_super_circuit_short_bytecode!(bytecode);
}
