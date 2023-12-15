use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn dup4_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        DUP4
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
