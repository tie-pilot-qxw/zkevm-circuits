use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[ignore = "remove ignore after XXX is finished"]
#[test]
fn calldataload_bytecode() {
    let bytecode = bytecode! {
        PUSH1(31)
        CALLDATALOAD
        STOP
    };
    let calldata = "123456789a";
    let (witness, ..) = test_super_circuit_short_bytecode!(bytecode, calldata);
    let mut buf = std::io::BufWriter::new(std::fs::File::create("demo.html").unwrap());
    witness.write_html(&mut buf);
}
