use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn prevrandao_bytecode() {
    let bytecode = bytecode! {
        DIFFICULTY // 0x44, alias for PREVRANDAO
        DIFFICULTY
        SUB
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
