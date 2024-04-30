use halo2_proofs::halo2curves::bn256::Fr;

use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::{bytecode, core, Witness};

use crate::gen_proof_params_and_write_file;

#[test]
fn init_proof_params() {
    let degree = log2_ceil(MAX_NUM_ROW);
    let mut witness = Witness::default();
    witness.bytecode.push(bytecode::Row::default()); // bytecode must have first row
    witness.core.push(core::Row::default()); // bytecode must have last row
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    gen_proof_params_and_write_file(degree, circuit)
}
