use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn dup1_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
        DUP1
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
