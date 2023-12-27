use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn dup10_bytecode() {
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
        DUP10
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
