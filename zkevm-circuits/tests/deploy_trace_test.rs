use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use std::fs::File;
use std::io::Read;
use trace_parser::read_trace_from_api_result_file;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{geth_data_test, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[ignore]
#[test]
fn test_deploy_trace() {
    const LONG_TEST_ROWS: usize = 8080;
    let trace = read_trace_from_api_result_file("test_data/deploy-trace.json");
    let mut hex_file = File::open("test_data/deploy-bytecode.txt").unwrap();
    let mut bytecodes = String::new();
    hex_file.read_to_string(&mut bytecodes).unwrap();
    if bytecodes.starts_with("0x") {
        bytecodes = bytecodes.split_off(2);
    }
    let bytecodes = hex::decode(bytecodes).unwrap();
    let witness = Witness::new(&geth_data_test(trace, &bytecodes, &[], true));
    let mut buf = std::io::BufWriter::new(File::create("demo.html").unwrap());
    witness.write_html(&mut buf);
    let witness_length = SuperCircuit::<
        Fr,
        LONG_TEST_ROWS,
        LONG_TEST_ROWS,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness);
    let circuit: SuperCircuit<
        Fr,
        LONG_TEST_ROWS,
        LONG_TEST_ROWS,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    > = SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();

    let k = log2_ceil(witness_length);
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
}
