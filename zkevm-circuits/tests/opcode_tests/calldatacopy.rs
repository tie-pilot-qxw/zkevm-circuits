use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn calldatacopy_bytecode() {
    let bytecode = bytecode! {
    PUSH1(1)
    PUSH1(2)
    PUSH1(0)
    CALLDATACOPY
    PUSH1(8)
    PUSH1(31)
    PUSH1(0)
    CALLDATACOPY
    STOP
    };
    let calldata = "123456789a";
    test_super_circuit_short_bytecode!(bytecode, calldata);
}
