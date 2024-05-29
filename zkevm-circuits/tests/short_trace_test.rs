use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use std::fs::File;
use std::io::Read;
use trace_parser::{read_log_from_api_result_file, read_trace_from_api_result_file};
use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{chunk_data_test, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[test]
#[ignore]
fn test_short_trace() {
    let trace = read_trace_from_api_result_file("test_data/short-trace.json");
    let mut hex_file = File::open("test_data/short-bytecode.txt").unwrap();
    let mut bytecodes = String::new();
    hex_file.read_to_string(&mut bytecodes).unwrap();
    if bytecodes.starts_with("0x") {
        bytecodes = bytecodes.split_off(2);
    }
    let bytecodes = hex::decode(bytecodes).unwrap();
    let receipt_log = read_log_from_api_result_file("test_data/short-log.json");
    let witness = Witness::new(&chunk_data_test(trace, &bytecodes, &[], false, receipt_log));
    witness.print_csv();
    let mut buf = std::io::BufWriter::new(File::create("demo.html").unwrap());
    witness.write_html(&mut buf);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();

    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW,
        MAX_CODESIZE,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
}
