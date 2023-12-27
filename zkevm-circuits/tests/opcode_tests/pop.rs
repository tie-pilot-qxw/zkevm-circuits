use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn pop_bytecode() {
    let bytecode = bytecode! {
        PUSH3(125985)
        POP
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
