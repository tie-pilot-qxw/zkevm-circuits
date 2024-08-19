// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{keygen_pk, ProvingKey};

use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use snark_verifier_sdk::halo2::gen_snark_shplonk;

use eth_types::geth_types::ChunkData;

use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness::Witness;

use crate::constants::{CHUNK_PARAMS_FILENAME, CHUNK_VK_FILENAME};
use crate::io::{read_params, try_to_read};
use crate::proof::chunk::ChunkProof;
use crate::util::{deserialize_vk, handler_chunk_data, serialize_vk};

#[derive(Debug)]
pub struct Prover<
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    pub(crate) params: ParamsKZG<Bn256>,
    pub(crate) pk: Option<ProvingKey<G1Affine>>,
    pub(crate) raw_vk: Vec<u8>,
}

impl<const MAX_NUM_ROW: usize, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    Prover<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let params = read_params(params_dir, &CHUNK_PARAMS_FILENAME).unwrap();
        let vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME).unwrap();

        Self {
            params,
            raw_vk: vk,
            pk: None,
        }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        match self.pk {
            Some(ref pk) => Some(serialize_vk(pk.get_vk())),
            None => Some(self.raw_vk.clone()),
        }
    }

    pub fn gen_chunk_proof(&mut self, chunk_data: ChunkData) -> Result<ChunkProof> {
        let start = start_timer!(|| format!("enter gen_chunk_proof, MAX_NUM_ROW: {}", MAX_NUM_ROW));

        let chunk_data = handler_chunk_data(chunk_data);

        let witness = Witness::new(&chunk_data);
        let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
            SuperCircuit::new_from_witness(&witness);
        let circuit = circuit.clone();
        let general_params = self.params.clone();

        let pk_time = start_timer!(|| "use pk or create pk");
        let pk = match self.pk {
            Some(ref pk) => pk.clone(),
            None => {
                let vk = deserialize_vk::<
                    SuperCircuit<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
                >(&self.raw_vk, ());
                let pk = keygen_pk(&general_params, vk, &circuit)?;
                self.pk = Some(pk.clone());
                pk
            }
        };
        end_timer!(pk_time);

        let snark_time = start_timer!(|| "generate snark");
        let snark = gen_snark_shplonk(&general_params, &pk, circuit, None::<String>);
        end_timer!(snark_time);

        end_timer!(start);
        ChunkProof::new(snark, Some(&pk))
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::BufReader;

    use eth_types::geth_types::ChunkData;

    use crate::chunk::Prover;
    use crate::constants::{
        DEFAULT_PROOF_PARAMS_DIR, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
    };
    use crate::test::proof_test::{get_default_chunk_trace_json, CHUNK_TEST_INIT};

    #[test]
    fn test_chunk_proof() {
        let _ = &*CHUNK_TEST_INIT;
        let param_dir = DEFAULT_PROOF_PARAMS_DIR;
        let asset_dir = DEFAULT_PROOF_PARAMS_DIR;
        let start = std::time::Instant::now();

        let mut prover =
            Prover::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                param_dir, asset_dir,
            );
        println!("init time:{:?}", start.elapsed());

        let file = File::open(get_default_chunk_trace_json(None)).expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        let _snark = prover.gen_chunk_proof(chunk_data).unwrap();
    }
}
