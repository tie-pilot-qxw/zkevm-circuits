use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn mstore8_bytecode() {
    let bytecode = bytecode! {
        PUSH2(0xFFFF)
        PUSH1(0)
        MSTORE8
        PUSH1 (0xFF)
        PUSH1 (1)
        MSTORE8
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
