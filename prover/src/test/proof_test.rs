// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{keygen_vk, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use halo2_proofs::SerdeFormat;
use once_cell::sync::Lazy;
use rand_chacha::rand_core::OsRng;

use eth_types::geth_types::ChunkData;
use eth_types::U256;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::{bytecode, public, Witness};

use crate::chunk::Prover;
use crate::constants::{
    DEFAULT_PROOF_PARAMS_DIR, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
};
use crate::proof::dump_proof_path;
use crate::test::create_all_file::complete_process;

pub fn get_default_proof_params_file_path(degree: u32) -> String {
    format!("{}/k{}.params", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_vk_file_path(degree: u32) -> String {
    format!("{}/k{}.vk", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_pk_file_path(degree: u32) -> String {
    format!("{}/k{}.pk", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_chunk_trace_json(name: Option<&str>) -> String {
    let file = name.unwrap_or("chunk_traces.json");
    format!("{}/{}", DEFAULT_PROOF_PARAMS_DIR, file)
}

pub fn write_proof_params<P: AsRef<Path>>(params: &ParamsKZG<Bn256>, file_path: P) {
    let f = File::create(file_path).unwrap();
    let mut bw = BufWriter::new(f);
    params.write(&mut bw).unwrap();
    bw.flush().unwrap();
}

pub fn write_proof_vk<P: AsRef<Path>>(vk: &VerifyingKey<G1Affine>, file_path: P) {
    let f = File::create(file_path).unwrap();
    let mut bw = BufWriter::new(f);
    vk.write(&mut bw, SerdeFormat::RawBytes).unwrap();
    bw.flush().unwrap();
}

pub fn init_proof_params() {
    let degree = log2_ceil(MAX_NUM_ROW_FOR_TEST);
    let proof_vk_file_path = get_default_proof_vk_file_path(degree);
    let proof_params_file_path = get_default_proof_params_file_path(degree);

    if file_exists(proof_params_file_path.as_str()) && file_exists(proof_vk_file_path.as_str()) {
        return;
    }

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
        cnt: Some(U256::one()),
        ..Default::default()
    });

    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let proof_params = ParamsKZG::<Bn256>::setup(degree, OsRng);
    write_proof_params(&proof_params, proof_params_file_path);

    let vk = keygen_vk(&proof_params, &circuit).unwrap();
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

fn file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}
fn dump_params_and_vk_proof() {
    // create vk and pk
    init_proof_params();

    // crate proof
    let param_dir = DEFAULT_PROOF_PARAMS_DIR;
    let asset_dir = DEFAULT_PROOF_PARAMS_DIR;

    let proof_file_name = dump_proof_path(param_dir, "k15");
    if file_exists(proof_file_name.as_str()) {
        return;
    }

    let start = std::time::Instant::now();

    let mut prover = Prover::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
        param_dir, asset_dir,
    );
    println!("init time:{:?}", start.elapsed());

    let file = File::open(get_default_chunk_trace_json(None)).expect("file should exist");
    let reader = BufReader::new(file);
    let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();
    todo!("use gpu");
    let proof = prover.gen_chunk_proof(chunk_data, &mut None).unwrap();
    proof.dump(DEFAULT_PROOF_PARAMS_DIR, "k15").unwrap()
}

pub static CHUNK_TEST_INIT: Lazy<()> = Lazy::new(|| dump_params_and_vk_proof());
pub static BATCH_TEST_INIT: Lazy<()> = Lazy::new(|| complete_process(false));

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io;
    use std::io::BufReader;

    use std::path::Path;

    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey};
    use halo2_proofs::poly::commitment::ParamsProver;
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };

    use rand_chacha::rand_core::OsRng;

    use eth_types::geth_types::ChunkData;

    use zkevm_circuits::super_circuit::SuperCircuit;
    use zkevm_circuits::util::{log2_ceil, SubCircuit};
    use zkevm_circuits::witness::Witness;

    use crate::chunk::Prover;
    use crate::constants::{MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
    use crate::io::read_params;

    use crate::test::proof_test::{
        get_default_chunk_trace_json, get_default_proof_vk_file_path, read_proof_vk_from_file,
        CHUNK_TEST_INIT, DEFAULT_PROOF_PARAMS_DIR,
    };
    use crate::util::handler_chunk_data;

    impl<
            const MAX_NUM_ROW: usize,
            const NUM_STATE_HI_COL: usize,
            const NUM_STATE_LO_COL: usize,
        > Prover<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
    {
        pub fn test_prover() -> Self {
            let params = read_params(DEFAULT_PROOF_PARAMS_DIR, "k15.params").unwrap();

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
                MAX_NUM_ROW_FOR_TEST,
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

        pub fn gen_zkevm_proof_for_test(
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
                get_default_proof_vk_file_path(log2_ceil(MAX_NUM_ROW)),
            );
            let pk = keygen_pk(&general_params, vk, &circuit).unwrap();
            todo!("use gpu");
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<_, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
                &general_params,
                &pk,
                &[circuit],
                &[&instance_refs],
                OsRng,
                &mut transcript,
                &mut None,
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

    #[test]
    fn test_prover_circuit() {
        let _ = &*CHUNK_TEST_INIT;
        let prover =
            Prover::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::test_prover();
        let file = File::open(get_default_chunk_trace_json(None)).expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        prover.test_circuit_mock_run(chunk_data);
    }

    #[test]
    fn test_verify_mock() {
        let _ = &*CHUNK_TEST_INIT;
        let param_dir = DEFAULT_PROOF_PARAMS_DIR;
        let asset_dir = DEFAULT_PROOF_PARAMS_DIR;
        let prover = Prover::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
            param_dir, asset_dir,
        );
        let file = File::open(get_default_chunk_trace_json(None)).expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();

        let (proof, _general_params, _pk, instance) =
            prover.gen_zkevm_proof_for_test(chunk_data.clone());

        // verify
        prover.verify_test(chunk_data, proof, instance);
    }
}
