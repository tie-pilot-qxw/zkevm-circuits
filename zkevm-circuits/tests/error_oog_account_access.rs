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

fn run_test(witness: Witness) {
    //print witness
    //witness.print_csv();

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
fn test_balance_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/balance_out_of_gas/block_info.json",
        "test_data/oog_account_access/balance_out_of_gas/tx_info.json",
        "test_data/oog_account_access/balance_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/balance_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/balance_out_of_gas/bytecode.json",
    ));
    run_test(witness);
}

#[test]
fn test_sub_call_balance_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/sub_call_balance_out_of_gas/block_info.json",
        "test_data/oog_account_access/sub_call_balance_out_of_gas/tx_info.json",
        "test_data/oog_account_access/sub_call_balance_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/sub_call_balance_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/sub_call_balance_out_of_gas/bytecode.json",
    ));
    run_test(witness);
}

#[test]
fn test_extcodesize_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/extcodesize_out_of_gas/block_info.json",
        "test_data/oog_account_access/extcodesize_out_of_gas/tx_info.json",
        "test_data/oog_account_access/extcodesize_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/extcodesize_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/extcodesize_out_of_gas/bytecode.json",
    ));

    run_test(witness);
}
#[test]
fn test_sub_call_extcodesize_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/sub_call_extcodesize_out_of_gas/block_info.json",
        "test_data/oog_account_access/sub_call_extcodesize_out_of_gas/tx_info.json",
        "test_data/oog_account_access/sub_call_extcodesize_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/sub_call_extcodesize_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/sub_call_extcodesize_out_of_gas/bytecode.json",
    ));
    run_test(witness);
}

#[test]
fn test_extcodehash_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/extcodehash_out_of_gas/block_info.json",
        "test_data/oog_account_access/extcodehash_out_of_gas/tx_info.json",
        "test_data/oog_account_access/extcodehash_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/extcodehash_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/extcodehash_out_of_gas/bytecode.json",
    ));

    run_test(witness);
}
#[test]
fn test_sub_call_extcodehash_out_of_gas_trace() {
    // gen witness
    let witness = Witness::new(&get_chunk_data(
        "test_data/oog_account_access/sub_call_extcodehash_out_of_gas/block_info.json",
        "test_data/oog_account_access/sub_call_extcodehash_out_of_gas/tx_info.json",
        "test_data/oog_account_access/sub_call_extcodehash_out_of_gas/tx_debug_trace.json",
        "test_data/oog_account_access/sub_call_extcodehash_out_of_gas/receipt_info.json",
        "test_data/oog_account_access/sub_call_extcodehash_out_of_gas/bytecode.json",
    ));
    run_test(witness);
}
