use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn basefee_bytecode() {
    let bytecode = bytecode! {
        BASEFEE
        BASEFEE
        SUB
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
