use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn gasprice_bytecode() {
    let bytecode = bytecode! {
        GASPRICE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
