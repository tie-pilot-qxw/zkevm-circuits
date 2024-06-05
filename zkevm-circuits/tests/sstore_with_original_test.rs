use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_chunk_data, log2_ceil, preprocess_trace, SubCircuit};
use zkevm_circuits::witness::Witness;

#[test]
fn test_sstore_with_original() {
    // gen witness
    let mut chunk_data = get_chunk_data(
        "test_data/sstore_with_original/trace/block_info.json",
        "test_data/sstore_with_original/trace/tx_info.json",
        "test_data/sstore_with_original/trace/second_invoke.json",
        "test_data/sstore_with_original/trace/tx_receipt.json",
        "test_data/sstore_with_original/trace/bytecode.json",
    );
    preprocess_trace(&mut chunk_data.blocks[0].geth_traces[0]);
    let witness = Witness::new(&chunk_data);

    #[cfg(not(feature = "fast_test"))]
    const MAX_NUM_ROW_FOR_TEST: usize = 262200;
    #[cfg(feature = "fast_test")]
    const MAX_NUM_ROW_FOR_TEST: usize = 131072; // k=17

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, 7000, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);

    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        7000,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
}
