use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn origin_bytecode() {
    let bytecode = bytecode! {
        ORIGIN
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
