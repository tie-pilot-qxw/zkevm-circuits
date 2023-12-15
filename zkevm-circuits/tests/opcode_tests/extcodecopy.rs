use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn extcodecopy_bytecode() {
    let address = U256::from_str_radix("0x43a61f3f4c73ea0d444c5c1c1a8544067a86219b", 16).unwrap();
    let dest_offset: i32 = 0;
    let offset: i32 = 31;
    let size: i32 = 8;
    let bytecode = bytecode! {
        PUSH1(size)
        PUSH1(offset)
        PUSH1(dest_offset)
        CODECOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
