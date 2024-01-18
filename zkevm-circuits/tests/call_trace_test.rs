use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_geth_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[test]
fn test_call_trace() {
    // gen witness
    let witness = Witness::new(&get_geth_data(
        "test_data/call_test/trace/block_info.json",
        "test_data/call_test/trace/tx_info.json",
        "test_data/call_test/trace/tx_debug_trace.json",
        "test_data/call_test/trace/tx_receipt.json",
        "test_data/call_test/trace/bytecode.json",
    ));
    //print witness
    //witness.print_csv();

    let circuit: SuperCircuit<Fr, 6000, 5000, 10, 10> = SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<Fr, 6000, 5000, 10, 10>::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
}
