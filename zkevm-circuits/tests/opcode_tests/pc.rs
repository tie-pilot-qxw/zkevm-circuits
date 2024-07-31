use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn pc_bytecode() {
    let bytecode = bytecode! {
        PC       // Offset 0
        PC       // Offset 1
        JUMPDEST // Offest 2
        PC       // Offset 3
        PUSH1(1)  // Offset 4
        PC       // Offset 6 (previous instructions takes 2 bytes)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
