use crate::test_super_circuit_short_bytecode;
use eth_types::{bytecode, U256};

#[test]
fn create_bytecode() {
    // let a = U256::from_str_radix(
    //     "0x63FFFFFFFF6000526004601CF3",
    //     16,
    // )
    // .unwrap();
    // let bytecode = bytecode! {
    //     PUSH13(a)
    //     PUSH1(0)
    //     MSTORE
    //     PUSH1(13)
    //     PUSH1(0)
    //     PUSH1(0)
    //     CREATE
    //     STOP
    // };
    let bytecode = bytecode! {
        PUSH1(0)
        PUSH1(0)
        PUSH1(9)
        CREATE
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}