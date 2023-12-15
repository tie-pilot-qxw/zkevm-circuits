use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn callvalue_bytecode() {
    let bytecode = bytecode! {
        CALLVALUE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
