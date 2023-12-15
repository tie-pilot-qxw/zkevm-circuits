use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn coinbase_bytecode() {
    let bytecode = bytecode! {
        COINBASE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
