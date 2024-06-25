use std::env;

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
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
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
    let (proof_params, proof_pk) =
        gen_proof_params::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
            degree, chunk_data,
        );

    // step2: run and verify circuit
    run_circuit::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
        id,
        chunk_data,
        bench_round,
        proof_params,
        proof_pk,
    );
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
    let proof_params = ParamsKZG::<Bn256>::setup(degree, OsRng);

    // gen proof vk
    let proof_vk = keygen_vk(&proof_params, &circuit).expect("keygen_vk should not fail");

    // gen proof pk
    let proof_pk = keygen_pk(&proof_params, proof_vk, &circuit).expect("keygen_pk should not fail");

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
    let witness = Witness::new(&chunk_data);

    // Create a circuit
    let circuit_msg = format!(
        "{}/{}/Create a new SubCircuit from witness.",
        CREATE_CIRCUIT, id
    );
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance: Vec<Vec<Fr>> = circuit.instance();
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

    // create proof and verify
    for i in 0..bench_round {
        let circuit = circuit.clone();
        let general_params = proof_params.clone();
        let pk = proof_pk.clone();

        // Create a proof
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

        // Verify the proof
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
    }
}

mod test {
    use crate::util::handler_chunk_data;
    use crate::zkevm::proof_test::run_benchmark;
    use eth_types::geth_types::ChunkData;
    use std::fs::File;
    use std::io::BufReader;

    const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = 21000;
    const DEPLOY_MAX_CODE_SIZE_FOR_TEST: usize = 7000;

    #[test]
    fn test_prover_json() {
        let file =
            File::open("./src/zkevm/test_data/chunk_traces.json").expect("file should exist");
        let reader = BufReader::new(file);
        let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();
        let chunk_data = handler_chunk_data(chunk_data);

        let degree: u32 = 15;

        run_benchmark::<DEPLOY_MAX_NUM_ROW_FOR_TEST, DEPLOY_MAX_CODE_SIZE_FOR_TEST>(
            "prover json benchmark",
            &chunk_data,
            degree,
        );
    }
}
