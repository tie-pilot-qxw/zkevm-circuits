use crate::{gen_random_hex_str, get_func_name, test_super_circuit_short_bytecode};
use eth_types::{bytecode, U256};

#[test]
fn test_codesize() {
    let a = U256::from_str_radix("0x01", 16).unwrap();
    let bytecode = bytecode! {
        PUSH1(a)
        POP
        CODESIZE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
