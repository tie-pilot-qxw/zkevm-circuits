use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn gaslimit_bytecode() {
    let bytecode = bytecode! {
        GASLIMIT
        GASLIMIT
        SUB
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
