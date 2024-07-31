use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_chunk_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[cfg(not(feature = "fast_test"))]
const MAX_NUM_ROW_FOR_TEST: usize = 262200;
#[cfg(feature = "fast_test")]
const MAX_NUM_ROW_FOR_TEST: usize = 21000;

#[test]
fn test_erc20_t01_a_deploy() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/erc20_test/trace/t01_a_deploy_erc20/block_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_debug_trace.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_receipt.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/bytecode.json",
    ));
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);

    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_erc20_t02_a_transfer_b_200() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/erc20_test/trace/t02_a_transfer_b_200/block_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/bytecode.json",
    ));

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<Fr, MAX_NUM_ROW_FOR_TEST, 10, 10>::num_rows(
        &witness,
    ));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_erc20_t03_a_approve_c_200() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/erc20_test/trace/t03_a_approve_c_200/block_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_receipt.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/bytecode.json",
    ));

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_erc20_t04_c_transfer_from_a_b_200() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/block_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/bytecode.json",
    ));

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}
