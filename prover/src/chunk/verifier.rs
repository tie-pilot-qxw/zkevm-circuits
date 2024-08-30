// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::poly::commitment::ParamsProver;

use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;

use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use log::info;
use snark_verifier_sdk::halo2::{PoseidonTranscript, POSEIDON_SPEC};
use snark_verifier_sdk::NativeLoader;

use crate::constants::{CHUNK_PARAMS_FILENAME, CHUNK_VK_FILENAME};
use zkevm_circuits::super_circuit::SuperCircuit;

use crate::io::{read_params, try_to_read};

use crate::proof::Proof;
use crate::util::{deserialize_vk, serialize_vk};

#[derive(Debug)]
pub struct Verifier<
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
}

impl<const MAX_NUM_ROW: usize, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    Verifier<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        Self { params, vk }
    }

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let params = read_params(params_dir, &CHUNK_PARAMS_FILENAME).unwrap();
        let raw_vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME);

        let vk = deserialize_vk::<SuperCircuit<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>(
            raw_vk.as_ref().unwrap(),
            (),
        );

        Self::new(params, vk)
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> bool {
        // Verify the proof
        let instances = proof.instances();
        let instance_refs: Vec<&[Fr]> = instances.iter().map(|v| &v[..]).collect();

        let mut verifier_transcript = PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(
            proof.proof(),
            POSEIDON_SPEC.clone(),
        );
        let strategy = AccumulatorStrategy::new(self.params.verifier_params());

        match verify_proof::<_, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &self.params.verifier_params(),
            &self.vk,
            strategy,
            &[&instance_refs],
            &mut verifier_transcript,
        ) {
            Ok(_p) => true,
            Err(e) => {
                info!("verify failed: {}", e.to_string());
                false
            }
        }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        Some(serialize_vk(&self.vk))
    }
}

#[cfg(test)]
mod test {
    use crate::chunk::Verifier;
    use crate::constants::{
        DEFAULT_PROOF_PARAMS_DIR, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
    };
    use crate::proof::Proof;
    use crate::test::proof_test::CHUNK_TEST_INIT;

    #[test]
    fn test_verify() {
        let _ = &*CHUNK_TEST_INIT;
        let param_dir = DEFAULT_PROOF_PARAMS_DIR;
        let asset_dir = DEFAULT_PROOF_PARAMS_DIR;

        let verifier =
            Verifier::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                param_dir, asset_dir,
            );

        let proof = Proof::from_json_file(DEFAULT_PROOF_PARAMS_DIR, "k15");
        let result = verifier.verify_chunk_proof(proof.unwrap());
        assert!(result)
    }
}
