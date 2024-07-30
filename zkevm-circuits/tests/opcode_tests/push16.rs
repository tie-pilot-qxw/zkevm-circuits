use crate::gen_random_hex_str;
use crate::get_func_name;
use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, Bytecode, U256};

#[test]
fn push16_bytecode() {
    let func_name = get_func_name!().to_string();
    let my_vec: Vec<char> = func_name.chars().collect();
    let num_byte = usize::try_from(my_vec[4].to_digit(10).unwrap()).unwrap();
    let str1 = gen_random_hex_str(num_byte * 2);
    let str2 = gen_random_hex_str(num_byte * 2);

    let first = U256::from_str_radix(&str1, 16).unwrap();
    let second = U256::from_str_radix(&str2, 16).unwrap();
    let bytecode = bytecode! {
        PUSH16(first)
        PUSH16(second)
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
#[test]
fn push16_out_of_bounds() {
    // 6f2f00000000000000000000000000000000
    // Step { pc: 0x0000, op: PUSH16, gas: 9999979000, gas_cost: 3, depth: 1, error: None, stack: [], memory: [], storage: {} }
    // Step { pc: 0x0011, op: STOP, gas: 9999978997, gas_cost: 0, depth: 1, error: None, stack: [0x2f000000000000000000000000000000], memory: [], storage: {} }
    let machine_code = hex::decode("6f2f").unwrap();
    test_super_circuit_short_bytecode!(Bytecode::from_raw_unchecked(machine_code));
}
