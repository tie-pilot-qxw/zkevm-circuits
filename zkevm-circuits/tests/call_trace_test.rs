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
fn test_call_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/call_test/trace/block_info.json",
        "test_data/call_test/trace/tx_info.json",
        "test_data/call_test/trace/tx_debug_trace.json",
        "test_data/call_test/trace/tx_receipt.json",
        "test_data/call_test/trace/bytecode.json",
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
fn test_staticcall_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_test/trace/staticcall/block_info.json",
        "test_data/static_delegate_call_test/trace/staticcall/tx_info.json",
        "test_data/static_delegate_call_test/trace/staticcall/tx_debug_trace.json",
        "test_data/static_delegate_call_test/trace/staticcall/tx_receipt.json",
        "test_data/static_delegate_call_test/trace/staticcall/bytecode.json",
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
fn test_delegatecall_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_test/trace/delegatecall/block_info.json",
        "test_data/static_delegate_call_test/trace/delegatecall/tx_info.json",
        "test_data/static_delegate_call_test/trace/delegatecall/tx_debug_trace.json",
        "test_data/static_delegate_call_test/trace/delegatecall/tx_receipt.json",
        "test_data/static_delegate_call_test/trace/delegatecall/bytecode.json",
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
fn test_three_delegatecall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/delegatecall/01_three_delegatecall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/01_three_delegatecall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/01_three_delegatecall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/01_three_delegatecall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/01_three_delegatecall/bytecode.json",
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
fn test_two_delegatecall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/delegatecall/02_two_delegatecall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/02_two_delegatecall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/02_two_delegatecall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/02_two_delegatecall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/02_two_delegatecall/bytecode.json",
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
fn test_delegatecall_call() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/delegatecall/03_delegatecall_call/block_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/03_delegatecall_call/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/03_delegatecall_call/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/03_delegatecall_call/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/03_delegatecall_call/bytecode.json",
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
fn test_delegatecall_staticcall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/delegatecall/04_delegatecall_staticcall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/04_delegatecall_staticcall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/04_delegatecall_staticcall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/04_delegatecall_staticcall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/delegatecall/04_delegatecall_staticcall/bytecode.json",
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
fn test_three_call() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/call/01_three_call/block_info.json",
        "test_data/static_delegate_call_three_test/trace/call/01_three_call/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/call/01_three_call/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/call/01_three_call/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/call/01_three_call/bytecode.json",
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
fn test_two_call() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/call/02_two_call/block_info.json",
        "test_data/static_delegate_call_three_test/trace/call/02_two_call/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/call/02_two_call/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/call/02_two_call/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/call/02_two_call/bytecode.json",
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
fn test_call_delegatecall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/call/03_call_delegatecall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/call/03_call_delegatecall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/call/03_call_delegatecall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/call/03_call_delegatecall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/call/03_call_delegatecall/bytecode.json",
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
fn test_call_staticcall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/call/04_call_staticacall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/call/04_call_staticacall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/call/04_call_staticacall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/call/04_call_staticacall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/call/04_call_staticacall/bytecode.json",
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
fn test_three_staticcall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/staticcall/01_three_staticacall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/01_three_staticacall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/01_three_staticacall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/01_three_staticacall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/01_three_staticacall/bytecode.json",
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
fn test_two_staticcall() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/static_delegate_call_three_test/trace/staticcall/02_two_staticacall/block_info.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/02_two_staticacall/tx_info.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/02_two_staticacall/tx_debug_trace.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/02_two_staticacall/tx_receipt.json",
        "test_data/static_delegate_call_three_test/trace/staticcall/02_two_staticacall/bytecode.json",
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
