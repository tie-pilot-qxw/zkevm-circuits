use crate::gen_random_hex_str;
use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn log4_bytecode() {
    let size = 32;
    let offset = 0;
    let topic1: U256 = U256::from_str_radix(&gen_random_hex_str(64), 16).unwrap();
    let topic2: U256 = U256::from_str_radix(&gen_random_hex_str(64), 16).unwrap();
    let topic3: U256 = U256::from_str_radix(&gen_random_hex_str(64), 16).unwrap();
    let topic4: U256 = U256::from_str_radix(&gen_random_hex_str(64), 16).unwrap();

    let bytecode = bytecode! {
        PUSH32(topic4)
        PUSH32(topic3)
        PUSH32(topic2)
        PUSH32(topic1)
        PUSH32(size)
        PUSH32(offset)
        LOG4
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
