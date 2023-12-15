use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn jump_bytecode() {
    let bytecode = bytecode! {
        PUSH1(4)
        JUMP
        STOP
        JUMPDEST
        PUSH1(1)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}