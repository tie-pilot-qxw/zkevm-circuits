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
const MAX_NUM_ROW_FOR_TEST: usize = 2500;

#[test]
fn test_stack_underflow() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_stack_pointer/stack_underflow/block_info.json",
        "test_data/error_invalid_stack_pointer/stack_underflow/tx_info.json",
        "test_data/error_invalid_stack_pointer/stack_underflow/tx_debug_trace.json",
        "test_data/error_invalid_stack_pointer/stack_underflow/receipt_info.json",
        "test_data/error_invalid_stack_pointer/stack_underflow/bytecode.json",
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

// sub call overflow same as sub call underflow,
// so we only test sub call underflow.
#[test]
fn test_sub_call_underflow() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_stack_pointer/sub_call_underflow/block_info.json",
        "test_data/error_invalid_stack_pointer/sub_call_underflow/tx_info.json",
        "test_data/error_invalid_stack_pointer/sub_call_underflow/tx_debug_trace.json",
        "test_data/error_invalid_stack_pointer/sub_call_underflow/receipt_info.json",
        "test_data/error_invalid_stack_pointer/sub_call_underflow/bytecode.json",
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
fn test_stack_overflow() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_stack_pointer/stack_overflow/block_info.json",
        "test_data/error_invalid_stack_pointer/stack_overflow/tx_info.json",
        "test_data/error_invalid_stack_pointer/stack_overflow/tx_debug_trace.json",
        "test_data/error_invalid_stack_pointer/stack_overflow/receipt_info.json",
        "test_data/error_invalid_stack_pointer/stack_overflow/bytecode.json",
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
