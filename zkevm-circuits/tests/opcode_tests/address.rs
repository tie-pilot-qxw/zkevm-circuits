use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn address_bytecode() {
    let bytecode = bytecode! {
        ADDRESS
        ADDRESS
        SUB
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
