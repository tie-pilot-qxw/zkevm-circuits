// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_chunk_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

#[cfg(not(feature = "fast_test"))]
const MAX_NUM_ROW: usize = 262200;
#[cfg(feature = "fast_test")]
const MAX_NUM_ROW: usize = 40000;

#[test]
fn test_multi_block_erc20() {
    let mut blocks = get_chunk_data(
        "test_data/erc20_test/trace/t01_a_deploy_erc20/block_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_debug_trace.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_receipt.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/bytecode.json",
    );

    let block_2 = get_chunk_data(
        "test_data/erc20_test/trace/t02_a_transfer_b_200/block_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/bytecode.json",
    );

    let block_3 = get_chunk_data(
        "test_data/erc20_test/trace/t03_a_approve_c_200/block_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_receipt.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/bytecode.json",
    );

    let block_4 = get_chunk_data(
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/block_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/bytecode.json",
    );

    blocks.blocks.extend(block_2.blocks);
    blocks.blocks.extend(block_3.blocks);
    blocks.blocks.extend(block_4.blocks);
    blocks.history_hashes.push(257.into());
    blocks.history_hashes.push(258.into());
    blocks.history_hashes.push(259.into());

    let witness = Witness::new(&blocks);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}
