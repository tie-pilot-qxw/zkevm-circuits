use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

// #[ignore = "restore after begin_tx is fixed"]
#[test]
fn calldatacopy_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
        PUSH1(2)
        PUSH1(0)
        CALLDATACOPY
        STOP
    };
    let calldata = "123456789a";
    let (witness, ..) = test_super_circuit_short_bytecode!(bytecode, calldata);
    let mut buf = std::io::BufWriter::new(std::fs::File::create("demo.html").unwrap());
    witness.write_html(&mut buf);
}

#[test]
fn calldatacopy_without_calldata_bytecode() {
    let bytecode = bytecode! {
        PUSH1(1)
        PUSH1(2)
        PUSH1(0)
        CALLDATACOPY
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
