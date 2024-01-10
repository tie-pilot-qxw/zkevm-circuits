use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn calldatasize_bytecode() {
    let bytecode = bytecode! {
        CALLDATASIZE
        STOP
    };
    let calldata = "123456789a";
    let (witness, ..) = test_super_circuit_short_bytecode!(bytecode, calldata);
    let mut buf = std::io::BufWriter::new(std::fs::File::create("demo.html").unwrap());
    witness.write_html(&mut buf);
}
