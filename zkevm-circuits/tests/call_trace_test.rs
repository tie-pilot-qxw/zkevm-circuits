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
