use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn jumpi_bytecode() {
    let bytecode = bytecode! {
        PUSH1(0)
        PUSH1(10)
        JUMPI
        PUSH1(1)
        PUSH1(12)
        JUMPI  
        JUMPDEST
        STOP
        JUMPDEST
        PUSH1(1)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}