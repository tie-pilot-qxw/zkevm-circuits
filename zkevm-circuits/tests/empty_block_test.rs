use eth_types::geth_types::{ChunkData, GethData};
use eth_types::U256;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use trace_parser::read_block_from_api_result_file;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[cfg(not(feature = "fast_test"))]
const MAX_NUM_ROW: usize = 12200;

#[cfg(all(feature = "fast_test", not(feature = "no_public_hash_lookup")))]
const MAX_NUM_ROW: usize = 600;
const MAX_CODESIZE: usize = 1;

#[cfg(all(feature = "fast_test", feature = "no_public_hash_lookup"))]
const MAX_NUM_ROW: usize = 8133;

#[test]
fn test_multi_block_erc20() {
    let block1 = GethData {
        eth_block: read_block_from_api_result_file(
            "test_data/empty_block_test/trace/block_info_1.json",
        ),
        accounts: vec![],
        logs: vec![],
        geth_traces: vec![],
    };
    let block2 = GethData {
        eth_block: read_block_from_api_result_file(
            "test_data/empty_block_test/trace/block_info_2.json",
        ),
        accounts: vec![],
        logs: vec![],
        geth_traces: vec![],
    };
    let block3 = GethData {
        eth_block: read_block_from_api_result_file(
            "test_data/empty_block_test/trace/block_info_3.json",
        ),
        accounts: vec![],
        logs: vec![],
        geth_traces: vec![],
    };
    let block4 = GethData {
        eth_block: read_block_from_api_result_file(
            "test_data/empty_block_test/trace/block_info_4.json",
        ),
        accounts: vec![],
        logs: vec![],
        geth_traces: vec![],
    };
    let block5 = GethData {
        eth_block: read_block_from_api_result_file(
            "test_data/empty_block_test/trace/block_info_5.json",
        ),
        accounts: vec![],
        logs: vec![],
        geth_traces: vec![],
    };

    let chunk = ChunkData {
        chain_id: U256::from(0x7a69),
        history_hashes: vec![0.into(); 261],
        blocks: vec![block1, block2, block3, block4, block5],
    };

    let witness = Witness::new(&chunk);
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
    prover.assert_satisfied();
}
