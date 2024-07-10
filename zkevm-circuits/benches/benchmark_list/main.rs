mod call_trace;
mod super_circuit;

mod erc20;
mod init_proof_params;

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use ark_std::{end_timer, start_timer};
use eth_types::geth_types::ChunkData;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
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
use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness::Witness;

// environment variables key
const CMD_ENV_ROUND: &str = "ROUND";
const CMD_ENV_USEFILE: &str = "USEFILE";
// default bench round
const DEFAULT_BENCH_ROUND: usize = 1;
const DEFAULT_BENCH_USEFILE: bool = false;
// circuit summary prefix, degree, max_num_row, round
const CIRCUIT_SUMMARY: &str = "[Circuit summary]";
// generate witness , gw
const GENERATE_WITNESS: &str = "[Generate witness]";
// create circuit ,cc
const CREATE_CIRCUIT: &str = "[Create circuit]";
// create proof ,cp
const CREATE_PROOF: &str = "[Create_proof]";
// verify proof , vp
const VERIFY_PROOF: &str = "[Verify proof]";
// default ptah to save proof params
pub const DEFAULT_PROOF_PARAMS_DIR: &str = "./test_data";

pub fn run_benchmark<const MAX_NUM_ROW: usize, const MAX_CODESIZE: usize>(
    id: &str,
    chunk_data: &ChunkData,
    degree: u32,
) {
    // get round from environment variables
    let round_val_str = env::var(CMD_ENV_ROUND).unwrap_or_else(|_| "".to_string());
    let bench_round: usize = round_val_str
        .parse()
        .unwrap_or_else(|_| DEFAULT_BENCH_ROUND);

    let usefile_val_str = env::var(CMD_ENV_USEFILE).unwrap_or_else(|_| "".to_string());
    let bench_usefile: bool = usefile_val_str
        .parse()
        .unwrap_or_else(|_| DEFAULT_BENCH_USEFILE);

    println!(
        "{}/id:{}, max_num_row:{}, max_code_size:{}, degree:{}, round:{}, use params file:{}",
        CIRCUIT_SUMMARY, id, MAX_NUM_ROW, MAX_CODESIZE, degree, bench_round, bench_usefile
    );

    // step1: get proof params
    let get_proof_params_start = start_timer!(|| "get proof params");
    let (proof_params, proof_pk) = if bench_usefile {
        get_proof_params_from_file::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
            get_default_proof_params_file_path(degree),
            get_default_proof_vk_file_path(degree),
            get_default_proof_pk_file_path(degree),
        )
    } else {
        gen_proof_params::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
            degree, chunk_data,
        )
    };
    end_timer!(get_proof_params_start);

    // step2: run and verify circuit
    let run_and_verify_circuit_start = start_timer!(|| "run and verify circuit");
    run_circuit::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
        id,
        chunk_data,
        bench_round,
        proof_params,
        proof_pk,
    );
    end_timer!(run_and_verify_circuit_start);
}

fn gen_proof_params_and_write_file(
    degree: u32,
    circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
) {
    println!(
        "{}/max_num_row:{}, max_code_size:{}, degree:{}",
        CIRCUIT_SUMMARY, MAX_NUM_ROW, MAX_CODESIZE, degree
    );
    // gen proof params
    let gen_proof_params_start = start_timer!(|| "gen proof params");
    let proof_params = ParamsKZG::<Bn256>::setup(degree, OsRng);
    end_timer!(gen_proof_params_start);

    // write proof params
    let proof_params_file_path = get_default_proof_params_file_path(degree);
    let write_proof_params_start =
        start_timer!(|| format!("write proof params to {}", proof_params_file_path));
    write_proof_params(&proof_params, proof_params_file_path);
    end_timer!(write_proof_params_start);

    // gen proof vk
    let gen_proof_vk_start = start_timer!(|| "gen proof vk");
    let vk = keygen_vk(&proof_params, &circuit).expect("keygen_vk should not fail");
    end_timer!(gen_proof_vk_start);

    // write proof vk
    let proof_vk_file_path = get_default_proof_vk_file_path(degree);
    let write_proof_vk_start = start_timer!(|| format!("write proof vk to {}", proof_vk_file_path));
    write_proof_vk(&vk, proof_vk_file_path);
    end_timer!(write_proof_vk_start);

    // gen proof pk
    let gen_proof_pk_start = start_timer!(|| "gen proof pk");
    let pk = keygen_pk(&proof_params, vk, &circuit).expect("keygen_pk should not fail");
    end_timer!(gen_proof_pk_start);

    let proof_pk_file_path = get_default_proof_pk_file_path(degree);
    let write_proof_pk_start = start_timer!(|| format!("write proof pk to {}", proof_pk_file_path));
    write_proof_pk(&pk, proof_pk_file_path);
    end_timer!(write_proof_pk_start);
}

fn get_proof_params_from_file<
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    proof_params_file_path: String,
    _proof_vk_file_path: String,
    proof_pk_file_path: String,
) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    let read_proof_params_start =
        start_timer!(|| format!("read proof params form {}", proof_params_file_path));
    let proof_params = read_proof_params_from_file(proof_params_file_path);
    end_timer!(read_proof_params_start);

    // let read_proof_vk_start = start_timer!(|| format!("read proof vk form {}", proof_vk_file_path));
    // let proof_vk = read_proof_vk_from_file::<
    // 	MAX_NUM_ROW,
    // 	MAX_CODESIZE,
    // 	NUM_STATE_HI_COL,
    // 	NUM_STATE_LO_COL>(proof_vk_file_path);
    // end_timer!(read_proof_vk_start);

    let read_proof_pk_start = start_timer!(|| format!("read proof pk form {}", proof_pk_file_path));
    let proof_pk = read_proof_pk_from_file::<
        _,
        MAX_NUM_ROW,
        MAX_CODESIZE,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >(proof_pk_file_path);
    end_timer!(read_proof_pk_start);

    (proof_params, proof_pk)
}

fn gen_proof_params<
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    degree: u32,
    chunk_data: &ChunkData,
) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    let witness = Witness::new(chunk_data);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    // gen proof params
    let gen_proof_params_start = start_timer!(|| "gen proof params");
    let proof_params = ParamsKZG::<Bn256>::setup(degree, OsRng);
    end_timer!(gen_proof_params_start);

    // gen proof vk
    let gen_proof_vk_start = start_timer!(|| "gen proof vk");
    let proof_vk = keygen_vk(&proof_params, &circuit).expect("keygen_vk should not fail");
    end_timer!(gen_proof_vk_start);

    // gen proof pk
    let gen_proof_pk_start = start_timer!(|| "gen proof pk");
    let proof_pk = keygen_pk(&proof_params, proof_vk, &circuit).expect("keygen_pk should not fail");
    end_timer!(gen_proof_pk_start);

    (proof_params, proof_pk)
}

fn run_circuit<
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    id: &str,
    chunk_data: &ChunkData,
    bench_round: usize,
    proof_params: ParamsKZG<Bn256>,
    proof_pk: ProvingKey<G1Affine>,
) {
    // get witness for benchmark
    let witness_msg = format!(
        "{}/{}/Generate witness of one transaction's trace.",
        GENERATE_WITNESS, id
    );
    let witness_start = start_timer!(|| witness_msg);
    let witness = Witness::new(&chunk_data);
    end_timer!(witness_start);

    // Create a circuit
    let circuit_msg = format!(
        "{}/{}/Create a new SubCircuit from witness.",
        CREATE_CIRCUIT, id
    );
    let circuit_start = start_timer!(|| circuit_msg);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance: Vec<Vec<Fr>> = circuit.instance();
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
    end_timer!(circuit_start);

    // create proof and verify
    for i in 0..bench_round {
        let circuit = circuit.clone();
        let general_params = proof_params.clone();
        let pk = proof_pk.clone();

        // Create a proof
        let proof_msg = format!(
            "{}/{}/Create proof/Round {}/{}",
            CREATE_PROOF,
            id,
            i + 1,
            bench_round
        );
        let proof_start = start_timer!(|| proof_msg);
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<_, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            OsRng,
            &mut transcript,
        )
        .expect(format!("{}/proof generation should not fail", id).as_str());

        let proof = transcript.finalize();
        end_timer!(proof_start);

        // Verify the proof
        let verify_msg = format!(
            "{}/{}/Verify proof/Round {}/{}",
            VERIFY_PROOF,
            id,
            i + 1,
            bench_round
        );
        let verify_start = start_timer!(|| verify_msg);
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
        .expect(format!("{}/failed to verify bench circuit", id).as_str());
        end_timer!(verify_start);
    }
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

// Save proving key as raw bytes to a file
pub fn write_proof_pk<P: AsRef<Path>>(pk: &ProvingKey<G1Affine>, file_path: P) {
    let f = File::create(file_path).unwrap();
    let mut bw = BufWriter::new(f);
    pk.write(&mut bw, SerdeFormat::RawBytes).unwrap();
    bw.flush().unwrap();
}

pub fn read_proof_params_from_file<P: AsRef<Path>>(params_file_path: P) -> ParamsKZG<Bn256> {
    let f = File::open(params_file_path).unwrap();
    let mut reader = BufReader::new(f);
    ParamsKZG::<Bn256>::read(&mut reader).unwrap()
}

pub fn read_proof_vk_from_file<
    P: AsRef<Path>,
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    verifying_key_file_path: P,
) -> VerifyingKey<G1Affine> {
    let f = File::open(verifying_key_file_path).unwrap();
    let mut reader = BufReader::new(f);
    VerifyingKey::<G1Affine>::read::<
        _,
        SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    >(&mut reader, SerdeFormat::RawBytes, ())
    .unwrap()
}

pub fn read_proof_pk_from_file<
    P: AsRef<Path>,
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    providing_key_file_path: P,
) -> ProvingKey<G1Affine> {
    let f = File::open(providing_key_file_path).unwrap();
    let mut reader = BufReader::new(f);
    ProvingKey::<G1Affine>::read::<
        _,
        SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    >(&mut reader, SerdeFormat::RawBytes, ())
    .unwrap()
}

pub fn get_default_proof_params_file_path(degree: u32) -> String {
    format!("{}/k{}.params", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_vk_file_path(degree: u32) -> String {
    format!("{}/k{}.vk", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_pk_file_path(degree: u32) -> String {
    format!("{}/k{}.pk", DEFAULT_PROOF_PARAMS_DIR, degree)
}
