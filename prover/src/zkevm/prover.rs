// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, verify_proof, Circuit, ConstraintSystem, ProvingKey,
};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use log::info;
use rand_chacha::rand_core::OsRng;

use eth_types::geth_types::ChunkData;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

use crate::io::{read_params, try_to_read};
use crate::proof::Proof;
use crate::util::{deserialize_vk, handler_chunk_data, serialize_vk};

#[derive(Debug)]
pub struct Prover<
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    params: ParamsKZG<Bn256>,
    pk: Option<ProvingKey<G1Affine>>,
    raw_vk: Vec<u8>,
}

impl<const MAX_NUM_ROW: usize, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    Prover<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let mut cs = ConstraintSystem::<Fr>::default();
        SuperCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::configure(&mut cs);
        let minimum_rows = cs.minimum_rows();
        let rows = MAX_NUM_ROW + minimum_rows;
        let degree = log2_ceil(rows);

        let param_file_name = format!("k{}.params", degree);
        let vk_file_name = format!("k{}.vk", degree);
        let params = read_params(params_dir, &param_file_name).unwrap();
        let vk = try_to_read(assets_dir, &vk_file_name).unwrap();

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

    pub fn gen_chunk_proof(&mut self, chunk_data: ChunkData) -> Result<Proof> {
        info!("enter gen_chunk_proof, MAX_NUM_ROW: {}", MAX_NUM_ROW);
        let mut start = std::time::Instant::now();

        let chunk_data = handler_chunk_data(chunk_data);
        info!("handler_chunk_data finished, time: {:?}", start.elapsed());

        start = std::time::Instant::now();
        let witness = Witness::new(&chunk_data);
        let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
            SuperCircuit::new_from_witness(&witness);
        let instance: Vec<Vec<Fr>> = circuit.instance();
        let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
        let circuit = circuit.clone();
        let general_params = self.params.clone();

        info!("new_witness finished, time: {:?}", start.elapsed());
        start = std::time::Instant::now();

        let pk = match self.pk {
            Some(ref pk) => pk.clone(),
            None => {
                let vk = deserialize_vk::<
                    SuperCircuit<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
                >(&self.raw_vk, ());
                let pk =
                    keygen_pk(&general_params, vk, &circuit).expect("keygen_vk should not fail");
                self.pk = Some(pk.clone());
                pk
            }
        };
        info!("keygen_pk finished, time: {:?}", start.elapsed());
        start = std::time::Instant::now();

        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            OsRng,
            &mut transcript,
        )
        .map_err(|e| anyhow!("failed to create_proof: {e:?}"))?;
        let proof = transcript.finalize();

        info!("generate proof success, time:{:?}", start.elapsed());
        // verify the proof
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &general_params.verifier_params(),
            pk.get_vk(),
            strategy,
            &[&instance_refs],
            &mut verifier_transcript,
        )
        .map_err(|e| anyhow!("failed to verify proof: {e:?}"))?;

        info!("verify proof success");
        Ok(Proof::new(proof, instance, Some(&pk)))
    }
}

#[cfg(test)]
mod test {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
    use std::fs::File;
    use std::io;
    use std::io::{BufReader, BufWriter, Write};
    use std::path::Path;

    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey,
    };
    use halo2_proofs::poly::commitment::{Params, ParamsProver};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use halo2_proofs::SerdeFormat;
    use rand_chacha::rand_core::OsRng;

    use crate::io::read_params;
    use crate::util::handler_chunk_data;
    use eth_types::geth_types::ChunkData;
    use zkevm_circuits::super_circuit::SuperCircuit;
    use zkevm_circuits::util::{log2_ceil, SubCircuit};
    use zkevm_circuits::witness::{bytecode, public, Witness};

    use crate::zkevm::Prover;

    const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = 21000;

    const NUM_STATE_HI_COL: usize = 9;

    const NUM_STATE_LO_COL: usize = 9;

    impl<
            const MAX_NUM_ROW: usize,
            const NUM_STATE_HI_COL: usize,
            const NUM_STATE_LO_COL: usize,
        > Prover<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
    {
        pub fn test_prover() -> Self {
            let params = read_params("./src/zkevm/test_data", "k15.params").unwrap();

            Self {
                params,
                raw_vk: vec![],
                pk: None,
            }
        }
        pub fn test_circuit_mock_run(&self, chunk_data: ChunkData) {
            let chunk_data = handler_chunk_data(chunk_data);

            let witness = Witness::new(&chunk_data);
            let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
                SuperCircuit::new_from_witness(&witness);

            let k = log2_ceil(SuperCircuit::<
                Fr,
                MAX_NUM_ROW,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            >::num_rows(&witness));
            let prover = MockProver::<Fr>::run(k, &circuit, circuit.instance()).unwrap();
            if prover.verify().is_err() {
                let file_name = Path::new(file!()).file_stem().unwrap();
                let file_path = Path::new("../zkevm-circuits/test_data/tmp.html")
                    .with_file_name(file_name)
                    .with_extension("html");
                let mut buf = io::BufWriter::new(File::create(file_path).unwrap());
                witness.write_html(&mut buf);
            }
            prover.assert_satisfied();
        }

        pub fn verify_test(&self, chunk_data: ChunkData, proof: Vec<u8>, instance: Vec<Vec<Fr>>) {
            let chunk_data = handler_chunk_data(chunk_data);

            let witness = Witness::new(&chunk_data);
            let circuit: SuperCircuit<
                Fr,
                DEPLOY_MAX_NUM_ROW_FOR_TEST,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            > = SuperCircuit::new_from_witness(&witness);
            let circuit = circuit.clone();
            let general_params = self.params.clone();

            let vk = keygen_vk(&general_params, &circuit).unwrap();

            let mut verifier_transcript =
                Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
            let strategy = SingleStrategy::new(&general_params);
            let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

            verify_proof::<_, VerifierSHPLONK<'_, Bn256>, _, _, _>(
                &general_params.verifier_params(),
                &vk,
                strategy.clone(),
                &[&instance_refs],
                &mut verifier_transcript,
            )
            .expect("failed to verify bench circuit".to_string().as_str());
        }

        pub fn gen_chunk_proof_for_test(
            &self,
            chunk_data: ChunkData,
        ) -> (
            Vec<u8>,
            ParamsKZG<Bn256>,
            ProvingKey<G1Affine>,
            Vec<Vec<Fr>>,
        ) {
            let chunk_data = handler_chunk_data(chunk_data);

            let witness = Witness::new(&chunk_data);
            let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
                SuperCircuit::new_from_witness(&witness);
            let instance: Vec<Vec<Fr>> = circuit.instance();
            let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
            // let circuit2 = circuit.clone();
            let circuit = circuit.clone();
            let general_params = self.params.clone();

            let vk = read_proof_vk_from_file::<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
                "./src/zkevm/test_data/k15.vk",
            );
            let pk = keygen_pk(&general_params, vk, &circuit).unwrap();

            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<_, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
                &general_params,
                &pk,
                &[circuit],
                &[&instance_refs],
                OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail".to_string().as_str());
            let proof = transcript.finalize();

            // verify the proof
            let mut verifier_transcript =
                Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
            let strategy = SingleStrategy::new(&general_params);

            // let mut file = File::create("./src/zkevm/test_data/pk1").unwrap();
            // writeln!(file, "{:?}", pk).expect("panic message");

            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                SingleStrategy<'_, Bn256>,
            >(
                &general_params.verifier_params(),
                pk.get_vk(),
                strategy.clone(),
                &[&instance_refs],
                &mut verifier_transcript,
            )
            .expect("failed to verify bench circuit".to_string().as_str());

            (proof, general_params, pk, instance)
        }
    }
    pub fn get_default_proof_params_file_path(degree: u32) -> String {
        format!("{}/k{}.params", "./src/zkevm/test_data", degree)
    }

    pub fn write_proof_params<P: AsRef<Path>>(params: &ParamsKZG<Bn256>, file_path: P) {
        let f = File::create(file_path).unwrap();
        let mut bw = BufWriter::new(f);
        params.write(&mut bw).unwrap();
        bw.flush().unwrap();
    }

    pub fn get_default_proof_vk_file_path(degree: u32) -> String {
        format!("{}/k{}.vk", "./src/zkevm/test_data", degree)
    }

    pub fn write_proof_vk<P: AsRef<Path>>(vk: &VerifyingKey<G1Affine>, file_path: P) {
        let f = File::create(file_path).unwrap();
        let mut bw = BufWriter::new(f);
        vk.write(&mut bw, SerdeFormat::RawBytes).unwrap();
        bw.flush().unwrap();
    }

    fn init_proof_params() {
        let degree = log2_ceil(DEPLOY_MAX_NUM_ROW_FOR_TEST);
        let mut witness = Witness::default();
        witness.bytecode.push(bytecode::Row::default()); // bytecode must have first row
        witness
            .core
            .push(zkevm_circuits::witness::core::Row::default()); // bytecode must have last row
        for _ in 0..15 {
            witness.public.push(public::Row::default());
        }
        witness.public.push(public::Row {
            tag: public::Tag::ChainId,
            ..Default::default()
        });
        public::witness_post_handle(&mut witness);

        let circuit: SuperCircuit<
            Fr,
            DEPLOY_MAX_NUM_ROW_FOR_TEST,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        > = SuperCircuit::new_from_witness(&witness);
        let proof_params = ParamsKZG::<Bn256>::setup(degree, OsRng);
        let proof_params_file_path = get_default_proof_params_file_path(degree);
        write_proof_params(&proof_params, proof_params_file_path);

        let vk = keygen_vk(&proof_params, &circuit).unwrap();
        let proof_vk_file_path = get_default_proof_vk_file_path(degree);
        write_proof_vk(&vk, proof_vk_file_path);
    }

    pub fn read_proof_vk_from_file<
        P: AsRef<Path>,
        const MAX_NUM_ROW: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    >(
        verifying_key_file_path: P,
    ) -> VerifyingKey<G1Affine> {
        let f = File::open(verifying_key_file_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<
            _,
            SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(&mut reader, SerdeFormat::RawBytes, ())
        .unwrap()
    }

    pub fn read_proof_pk_from_file<
        P: AsRef<Path>,
        const MAX_NUM_ROW: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    >(
        providing_key_file_path: P,
    ) -> ProvingKey<G1Affine> {
        let f = File::open(providing_key_file_path).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<
            _,
            SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(&mut reader, SerdeFormat::RawBytes, ())
        .unwrap()
    }

    #[ignore]
    #[test]
    fn dump_params_and_vk_proof() {
        // create vk and pk
        init_proof_params();

        // crate proof
        let param_dir = "./src/zkevm/test_data";
        let asset_dir = "./src/zkevm/test_data";
        let start = std::time::Instant::now();

        let mut prover =
            Prover::<DEPLOY_MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                param_dir, asset_dir,
            );
        println!("init time:{:?}", start.elapsed());

        let file =
            File::open("./src/zkevm/test_data/chunk_traces.json").expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        let proof = prover.gen_chunk_proof(chunk_data).unwrap();
        proof.dump("./src/zkevm/test_data/", "k15").unwrap()
    }

    /// 先运行dump_params_and_vk_proof后测试
    #[ignore]
    #[test]
    fn test_prover() {
        let param_dir = "./src/zkevm/test_data";
        let asset_dir = "./src/zkevm/test_data";
        let start = std::time::Instant::now();

        let mut prover =
            Prover::<DEPLOY_MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                param_dir, asset_dir,
            );
        println!("init time:{:?}", start.elapsed());

        let file =
            File::open("./src/zkevm/test_data/chunk_traces.json").expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        prover.gen_chunk_proof(chunk_data).unwrap();
    }

    /// 先运行dump_params_and_vk_proof后测试
    #[ignore]
    #[test]
    fn test_prover_circuit() {
        let prover =
            Prover::<DEPLOY_MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::test_prover(
            );
        let file =
            File::open("./src/zkevm/test_data/chunk_traces.json").expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        prover.test_circuit_mock_run(chunk_data);
    }

    /// 先运行dump_params_and_vk_proof后测试
    #[ignore]
    #[test]
    fn test_verify_mock() {
        let param_dir = "./src/zkevm/test_data";
        let asset_dir = "./src/zkevm/test_data";
        let prover =
            Prover::<DEPLOY_MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                param_dir, asset_dir,
            );
        let file =
            File::open("./src/zkevm/test_data/chunk_traces.json").expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        let (proof, _general_params, _pk, instance) =
            prover.gen_chunk_proof_for_test(chunk_data.clone());

        // verify
        prover.verify_test(chunk_data, proof, instance);
    }
}
