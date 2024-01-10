use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn shl_bytecode() {
    let value = U256::from_str_radix("0x553e92e8bc0ae9a795ed1f57f3632d4d", 16).unwrap();
    for shift in (0..256).step_by(16) {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(shift)
            SHL // value<<shift
            STOP
        };
        test_super_circuit_short_bytecode!(bytecode);
    }
}
