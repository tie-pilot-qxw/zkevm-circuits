use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn xor_bytecode() {
    let a = U256::from_str_radix(
        "0x9F3A9ED44CC365B380A6BCF56590777A1C20CE55FE82D8D833B57B3AA2512F86",
        16,
    )
    .unwrap();
    let b = U256::from_str_radix(
        "0xE02D60384070BC8CB69D85B00340D77274D0E52104F75165A9012DD3F01D33E9",
        16,
    )
    .unwrap();
    let bytecode = bytecode! {
        PUSH32(b)
        PUSH32(a)
        XOR // a^b
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
