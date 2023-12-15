use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn swap11_bytecode() {
    let bytecode = bytecode! {
        PUSH1(2)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(1)
        SWAP11
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
