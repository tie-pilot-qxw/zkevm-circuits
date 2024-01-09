use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[ignore = "remove ignore after XXX is finished"]
#[test]
fn log0_bytecode() {
    let size = 32;
    let offset = 0;

    let bytecode = bytecode! {
        PUSH32(size)
        PUSH32(offset)
        LOG0
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
