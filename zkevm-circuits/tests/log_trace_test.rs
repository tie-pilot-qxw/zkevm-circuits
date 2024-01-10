use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_geth_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

// include log0, log1, log2, log3, log4
#[test]
fn test_log_trace() {
    // gen witness
    let witness = Witness::new(&get_geth_data(
        "test_data/log_test/trace/block_info.json",
        "test_data/log_test/trace/tx_info.json",
        "test_data/log_test/trace/tx_debug_trace.json",
        "test_data/log_test/trace/tx_receipt.json",
        "test_data/log_test/trace/bytecode.json",
    ));

    let circuit: SuperCircuit<Fr, 2230, 1400, 10, 10> = SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<Fr, 2230, 1400, 10, 10>::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
}
