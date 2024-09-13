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
const MAX_NUM_ROW_FOR_TEST: usize = 262200;
#[cfg(feature = "fast_test")]
const MAX_NUM_ROW_FOR_TEST: usize = 11000;

#[test]
fn test_root_invalid_jump() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_jump/root_invalid_jump/block_info.json",
        "test_data/error_invalid_jump/root_invalid_jump/tx_info.json",
        "test_data/error_invalid_jump/root_invalid_jump/tx_debug_trace.json",
        "test_data/error_invalid_jump/root_invalid_jump/receipt_info.json",
        "test_data/error_invalid_jump/root_invalid_jump/bytecode.json",
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
fn test_sub_call_invalid_jump() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_jump/sub_call_invalid_jump/block_info.json",
        "test_data/error_invalid_jump/sub_call_invalid_jump/tx_info.json",
        "test_data/error_invalid_jump/sub_call_invalid_jump/tx_debug_trace.json",
        "test_data/error_invalid_jump/sub_call_invalid_jump/receipt_info.json",
        "test_data/error_invalid_jump/sub_call_invalid_jump/bytecode.json",
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

    //print witness
    // let file_name = std::path::Path::new(file!()).file_stem().unwrap();
    // let file_path = std::path::Path::new("./test_data/tmp.html")
    //     .with_file_name(file_name)
    //     .with_extension("html");
    // let mut buf = std::io::BufWriter::new(std::fs::File::create(file_path).unwrap());
    // witness.write_html(&mut buf);

    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied();
}

/// dest超过了u64
#[test]
fn test_root_invalid_jump_dest_max_code() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_jump/root_invalid_jump_dest_max_code/block_info.json",
        "test_data/error_invalid_jump/root_invalid_jump_dest_max_code/tx_info.json",
        "test_data/error_invalid_jump/root_invalid_jump_dest_max_code/tx_debug_trace.json",
        "test_data/error_invalid_jump/root_invalid_jump_dest_max_code/receipt_info.json",
        "test_data/error_invalid_jump/root_invalid_jump_dest_max_code/bytecode.json",
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

/// dest超过code len
#[test]
fn test_root_invalid_jumpi() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_jump/root_invalid_jumpi/block_info.json",
        "test_data/error_invalid_jump/root_invalid_jumpi/tx_info.json",
        "test_data/error_invalid_jump/root_invalid_jumpi/tx_debug_trace.json",
        "test_data/error_invalid_jump/root_invalid_jumpi/receipt_info.json",
        "test_data/error_invalid_jump/root_invalid_jumpi/bytecode.json",
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
