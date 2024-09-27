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

/// Test for invalid opcode in root call
#[test]
fn test_root_invalid_opcode() {
    // Generate witness data from the invalid opcode trace
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_opcode/root_invalid_opcode/block_info.json",
        "test_data/error_invalid_opcode/root_invalid_opcode/tx_info.json",
        "test_data/error_invalid_opcode/root_invalid_opcode/tx_debug_trace.json",
        "test_data/error_invalid_opcode/root_invalid_opcode/receipt_info.json",
        "test_data/error_invalid_opcode/root_invalid_opcode/bytecode.json",
    ));

    // Create the super circuit using the witness
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);

    // Get the instance of the circuit
    let instance = circuit.instance();

    // Calculate the log2 ceiling of the number of rows
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));

    // Create a prover to run the circuit
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();

    // Assert the circuit satisfies all the constraints
    prover.assert_satisfied();
}

/// Test for invalid opcode in a sub-call
#[test]
fn test_sub_call_invalid_opcode() {
    let witness = Witness::new(&get_chunk_data(
        "test_data/error_invalid_opcode/sub_call_invalid_opcode/block_info.json",
        "test_data/error_invalid_opcode/sub_call_invalid_opcode/tx_info.json",
        "test_data/error_invalid_opcode/sub_call_invalid_opcode/tx_debug_trace.json",
        "test_data/error_invalid_opcode/sub_call_invalid_opcode/receipt_info.json",
        "test_data/error_invalid_opcode/sub_call_invalid_opcode/bytecode.json",
    ));

    // Create the super circuit using the witness
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);

    // Get the instance of the circuit
    let instance = circuit.instance();

    // Calculate the log2 ceiling of the number of rows
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW_FOR_TEST,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));

    // Create a prover to run the circuit
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();

    // Assert the circuit satisfies all the constraints
    prover.assert_satisfied();
}
