// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constants::{
    AGG_PARAMS_FILENAME, AGG_PK_FILENAME, AGG_VK_FILENAME, CHUNK_PROTOCOL_FILENAME,
};
use crate::io::{force_to_read, read_params, try_to_read};
use crate::proof::batch::BatchProof;
use crate::proof::chunk::ChunkProof;
use crate::proof::Proof;

use anyhow::Result;
use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{keygen_vk, JitProverEnv, ProvingKey};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use sha2::{Digest, Sha256};
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
use snark_verifier_sdk::halo2::aggregation::{
    AggregationCircuit, AggregationConfigParams, VerifierUniversality,
};
use snark_verifier_sdk::snark_verifier::halo2_base::gates::circuit::CircuitBuilderStage;
use snark_verifier_sdk::{gen_pk, CircuitExt, Snark, SHPLONK};

use std::path::PathBuf;

#[derive(Debug)]
pub struct Prover<const AGG_DEGREE: usize> {
    pub chunk_protocol: Vec<u8>,
    params: ParamsKZG<Bn256>,
    pk: Option<ProvingKey<G1Affine>>,
    /// 该vk以u8形式存在在内存里，不会反序列化，主要用于校验
    raw_vk: Vec<u8>,
    /// 用于存储和读取pk的路径
    pk_path: PathBuf,
}

impl<const AGG_DEGREE: usize> Prover<AGG_DEGREE> {
    /// 必须的文件：
    /// 1. protocol：用于验证chunk proof
    /// 2. raw_vk：外部调用者需要使用get_vk，用来Prover和Coordinator服务做vk的校验对比，但是我们不需要vk来初始化pk，Coordinator会直接将文件读取为Byte[]结构，不需要FFI；
    /// 3. params：生成vk、pk的必须值
    /// 可选：
    /// pk：如果文件存在，生成proof时优先读取内存，内存中不存在则读取文件，文件不存在时则使用vk生成并存储至文件，文件默认路径为assets_dir/agg_k25.pk；
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let chunk_protocol = force_to_read(assets_dir, &CHUNK_PROTOCOL_FILENAME);
        let raw_vk = try_to_read(assets_dir, &AGG_VK_FILENAME).unwrap();
        let params = read_params(params_dir, &AGG_PARAMS_FILENAME).unwrap();

        let mut path = PathBuf::from(assets_dir);
        path.push(AGG_PK_FILENAME.as_str());

        Self {
            chunk_protocol,
            raw_vk,
            params,
            pk: None,
            pk_path: path,
        }
    }

    /// 校验chunk proof的protocol和初始化时读取的protocol是否一致，包含一些计算过程中需要的公共值
    pub fn check_chunk_proofs(&self, chunk_proofs: &[ChunkProof]) -> bool {
        chunk_proofs.iter().enumerate().all(|(i, proof)| {
            let result = proof.protocol == self.chunk_protocol;
            if !result {
                log::error!(
                    "Non-match protocol of chunk-proof index-{}: expected = {:x}, actual = {:x}",
                    i,
                    Sha256::digest(&self.chunk_protocol),
                    Sha256::digest(&proof.protocol),
                );
            }

            result
        })
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        Some(self.raw_vk.clone())
    }

    /// 生成EVM Proof
    pub fn gen_agg_evm_proof(
        &mut self,
        chunk_proofs: Vec<ChunkProof>,
        output_dir: Option<&str>,
        env_info: &mut Option<JitProverEnv>
    ) -> Result<BatchProof> {
        let agg_time = start_timer!(|| "enter gen_agg_evm_proof function");
        let degree = AGG_DEGREE as u32;
        let lookup_bits = AGG_DEGREE - 1;
        let snarks: Vec<Snark> = chunk_proofs
            .iter()
            .map(|proof| proof.clone().to_snark())
            .collect();

        let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree,
                lookup_bits,
                ..Default::default()
            },
            &self.params,
            snarks.clone(),
            VerifierUniversality::None,
        );
        let agg_config = agg_circuit.calculate_params(Some(20));

        let gen_key_time = start_timer!(|| "Generating key");
        if self.pk.is_none() {
            let pk = gen_pk::<AggregationCircuit>(
                &self.params,
                &agg_circuit,
                Some(self.pk_path.as_path()),
            );
            self.pk = Some(pk);
        }
        let pk = self.pk.as_ref().unwrap();
        end_timer!(gen_key_time);

        // TODO https://github.com/axiom-crypto/snark-verifier/issues/25 ,后期bug修复,去除
        //  因当前axiom在加载pk的时候会丢失break point的bug存在,所以这里调用了一次keygen_vk来生成break_points信息
        let vk_time = start_timer!(|| "keygen_vk function");
        keygen_vk(&self.params, &agg_circuit).unwrap();
        end_timer!(vk_time);

        let break_points = agg_circuit.break_points();
        drop(agg_circuit);

        let proof_time = start_timer!(|| "generating proof");
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &self.params,
            snarks.clone(),
            VerifierUniversality::None,
        )
        .use_break_points(break_points.clone());

        let mut agg_circuit = agg_circuit.clone();
        agg_circuit.expose_previous_instances(false);
        let instances = agg_circuit.instances();
        let proof =
            gen_evm_proof_shplonk(&self.params, &pk, agg_circuit.clone(), instances.clone(), env_info);
        end_timer!(proof_time);

        let proof = Proof::new(proof, &instances, Some(&pk));
        let batch_proof = BatchProof::from(proof);
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, "k25")?;
        }
        end_timer!(agg_time);

        Ok(batch_proof)
    }
}

#[cfg(test)]
mod test {
    use crate::batch::prover::Prover;
    use crate::constants::{AGG_DEGREE_FOR_TEST, DEFAULT_PROOF_PARAMS_DIR};
    use crate::proof::chunk::ChunkProof;
    use crate::test::proof_test::BATCH_TEST_INIT;

    #[test]
    fn gen_agg_proof() {
        let _ = &*BATCH_TEST_INIT;
        let proof = ChunkProof::from_json_file(DEFAULT_PROOF_PARAMS_DIR, "k15");
        let mut prover = Prover::<AGG_DEGREE_FOR_TEST>::from_dirs(
            DEFAULT_PROOF_PARAMS_DIR,
            DEFAULT_PROOF_PARAMS_DIR,
        );
        let result = prover
            .gen_agg_evm_proof(vec![proof.unwrap()], Some(DEFAULT_PROOF_PARAMS_DIR), &mut None)
            .unwrap();
        result
            .dump(
                DEFAULT_PROOF_PARAMS_DIR,
                format!("batch_k{}", AGG_DEGREE_FOR_TEST).as_str(),
            )
            .unwrap()
    }
}
