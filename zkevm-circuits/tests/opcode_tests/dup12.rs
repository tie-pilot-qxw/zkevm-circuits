use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn dup12_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
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
        PUSH1(0)
        DUP12
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
