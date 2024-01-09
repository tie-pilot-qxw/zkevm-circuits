use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[ignore = "remove ignore after XXX is finished"]
#[test]
fn log1_bytecode() {
    let bytecode = bytecode! {
        PUSH1(0)
        PUSH1(0)
        PUSH1(0)
        LOG1
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
