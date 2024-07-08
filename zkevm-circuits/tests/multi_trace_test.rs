use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_multi_trace_chunk_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[cfg(not(feature = "fast_test"))]
const MAX_NUM_ROW: usize = 262200;
#[cfg(feature = "fast_test")]
const MAX_NUM_ROW: usize = 10200;
const MAX_CODESIZE: usize = 6900;

#[test]
fn test_multi_trace() {
    // 测试单区块多交易trace
    // 该用例仅使用一个合约，包含一个区块4笔交易，交易操作为1.部署合约 2.updateMyBalance 3. updateBalance 4. transfer
    let chunk_data = get_multi_trace_chunk_data(
        "test_data/multi_trace_test/trace/block_info.json",
        vec![
            "test_data/multi_trace_test/trace/step_01_deploy_tx_info.json",
            "test_data/multi_trace_test/trace/step_02_updateMyBalance_tx_info.json",
            "test_data/multi_trace_test/trace/step_03_updateBalance_tx_info.json",
            "test_data/multi_trace_test/trace/step_04_transfer_tx_info.json",
        ],
        vec![
            "test_data/multi_trace_test/trace/step_01_deploy_tx_debug_trace.json",
            "test_data/multi_trace_test/trace/step_02_updateMyBalance_tx_debug_trace.json",
            "test_data/multi_trace_test/trace/step_03_updateBalance_tx_debug_trace.json",
            "test_data/multi_trace_test/trace/step_04_transfer_tx_debug_trace.json",
        ],
        vec![
            "test_data/multi_trace_test/trace/step_01_deploy_tx_receipt.json",
            "test_data/multi_trace_test/trace/step_02_updateMyBalance_tx_receipt.json",
            "test_data/multi_trace_test/trace/step_03_updateBalance_tx_receipt.json",
            "test_data/multi_trace_test/trace/step_04_transfer_tx_receipt.json",
        ],
        "test_data/multi_trace_test/trace/bytecode.json",
    );

    let witness = Witness::new(&chunk_data);
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
