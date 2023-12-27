use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn jumpdest_bytecode() {
    let bytecode = bytecode! {
        JUMPDEST
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
