mod call_trace;
mod super_circuit;

mod erc20;

use ark_std::{end_timer, start_timer};
use eth_types::geth_types::GethData;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::env;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness::Witness;

// environment variables key
const CMD_ENV_ROUND: &str = "ROUND";

// default bench round
const DEFAULT_BENCH_ROUND: usize = 3;

pub fn run_benchmark<const MAX_NUM_ROW_FOR_BENCH: usize, const MAX_CODESIZE_FOR_BENCH: usize>(
    id: &str,
    geth_data: &GethData,
    degree: u32,
    default_bench_round: usize,
) {
    println!(
        "id:{}, max_num_row:{}, max_code_size:{}",
        id, MAX_NUM_ROW_FOR_BENCH, MAX_CODESIZE_FOR_BENCH
    );

    // get round from environment variables
    let round_val_str = env::var(CMD_ENV_ROUND).unwrap_or_else(|_| "".to_string());
    let bench_round: usize = round_val_str
        .parse()
        .unwrap_or_else(|_| default_bench_round);

    #[cfg(feature = "benches")]
    println!(
        "--------start {} benchmark, round:{}--------",
        id, bench_round
    );
    #[cfg(not(feature = "benches"))]
    println!("--------start {} benchmark--------", id);

    // get witness for benchmark
    let witness_msg = format!("{}/Generate witness of one transaction's trace", id);
    let witness_start = start_timer!(|| witness_msg);
    let witness = Witness::new(&geth_data);
    end_timer!(witness_start);

    // Create a circuit
    let circuit_msg = format!("{}/Create a new SubCircuit from witness", id);
    let circuit_start = start_timer!(|| circuit_msg);
    let circuit: SuperCircuit<
        Fr,
        MAX_NUM_ROW_FOR_BENCH,
        MAX_CODESIZE_FOR_BENCH,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    > = SuperCircuit::new_from_witness(&witness);
    let instance: Vec<Vec<Fr>> = circuit.instance();
    end_timer!(circuit_start);

    println!(
        "{}/length {} and {}",
        id,
        instance[0].len(),
        instance[1].len()
    );
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

    // Bench setup generation
    let setup_msg = format!("{}/Setup with degree = {}", id, degree);
    let setup_start = start_timer!(|| setup_msg);
    let mut rng = ChaChaRng::seed_from_u64(2);
    let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
    end_timer!(setup_start);

    // Initialize the proving key
    let setup_msg = format!("{}/Initialize the proving key", id);
    let init_proving_key_setup_start = start_timer!(|| setup_msg);

    let keygen_vk_setup_start = start_timer!(|| format!("{}/Keygen vk", id));
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    end_timer!(keygen_vk_setup_start);

    let keygen_pk_setup_start = start_timer!(|| format!("{}/Keygen pk", id));
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
    end_timer!(keygen_pk_setup_start);

    end_timer!(init_proving_key_setup_start);

    // Create proof and verify.
    {
        let circuit = circuit.clone();
        let rng = rng.clone();
        let general_params = general_params.clone();
        let pk = pk.clone();

        // Create a proof
        let proof_msg = format!("{}/Create proof", id);
        let proof_start = start_timer!(|| proof_msg);

        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<
                _,
                MAX_NUM_ROW_FOR_BENCH,
                MAX_CODESIZE_FOR_BENCH,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            >,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            rng,
            &mut transcript,
        )
        .expect(format!("{}/proof generation should not fail", id).as_str());
        let proof = transcript.finalize();
        end_timer!(proof_start);

        println!("{}/Proof length: {}", id, proof.len());

        // Verify the proof
        let verify_msg = format!("{}/Verify proof", id);
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
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&instance_refs],
            &mut verifier_transcript,
        )
        .expect(format!("{}/failed to verify bench circuit", id).as_str());
        end_timer!(verify_start);
    }

    #[cfg(feature = "benches")]
    for i in 0..bench_round {
        let circuit = circuit.clone();
        let rng = rng.clone();
        let general_params = general_params.clone();
        let pk = pk.clone();

        // Create a proof
        let proof_msg = format!("{}/Round {} of {}: Create proof", id, i + 1, bench_round);
        let proof_start = start_timer!(|| proof_msg);
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<
                _,
                MAX_NUM_ROW_FOR_BENCH,
                MAX_CODESIZE_FOR_BENCH,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            >,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            rng,
            &mut transcript,
        )
        .expect(format!("{}/proof generation should not fail", id).as_str());

        end_timer!(proof_start);
    }

    println!("--------{} benchmark over --------", id);
}
