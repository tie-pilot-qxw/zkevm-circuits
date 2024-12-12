// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::gen_proof_params_and_write_file;
use eth_types::U256;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::constant::{
    MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL, PUBLIC_NUM_BEGINNING_PADDING_ROW,
};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::{bytecode, core, public, Witness};

#[test]
fn init_proof_params() {
    let degree = log2_ceil(MAX_NUM_ROW);
    let mut witness = Witness::default();
    witness.bytecode.push(bytecode::Row::default()); // bytecode must have first row
    witness.core.push(core::Row::default()); // bytecode must have last row
    for _ in 0..PUBLIC_NUM_BEGINNING_PADDING_ROW {
        witness.public.push(public::Row::default());
    }
    witness.public.push(public::Row {
        tag: public::Tag::ChainId,
        cnt: Some(U256::one()),
        ..Default::default()
    });

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    gen_proof_params_and_write_file(degree, circuit)
}
