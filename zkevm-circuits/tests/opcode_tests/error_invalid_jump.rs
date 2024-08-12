use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn error_invalid_jumpi_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
        PUSH1(4)
        JUMPI
        PUSH1(1)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn error_invalid_jump_bytecode() {
    let bytecode = bytecode! {
        PUSH1(4)
        JUMP
        PUSH1(1)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}

#[test]
fn error_invalid_dest_bytecode() {
    let bytecode = bytecode! {
        PUSH1(9)
        JUMP
        PUSH1(1)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
