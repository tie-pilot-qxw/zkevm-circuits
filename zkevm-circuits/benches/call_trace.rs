#[macro_use]
extern crate criterion;

use criterion::Criterion;
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
use zkevm_circuits::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_geth_data, SubCircuit};
use zkevm_circuits::witness::Witness;

const MAX_CODESIZE_FOR_CALL_TRACE: usize = 4220;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("create proof");
    group.sample_size(10);

    // get witness for bench
    let witness = Witness::new(&get_geth_data(
        "test_data/call_test/trace/block_info.json",
        "test_data/call_test/trace/tx_info.json",
        "test_data/call_test/trace/tx_debug_trace.json",
        "test_data/call_test/trace/tx_receipt.json",
        "test_data/call_test/trace/bytecode.json",
    ));

    let circuit: SuperCircuit<
        Fr,
        MAX_NUM_ROW,
        MAX_CODESIZE_FOR_CALL_TRACE,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    > = SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();

    println!("length {} and {}", instance[0].len(), instance[1].len());
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

    let degree = 14;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree = 19;
    // bench setup generation
    let mut rng = ChaChaRng::seed_from_u64(2);
    let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    // Initialize the proving key
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");

    {
        let circuit = circuit.clone();
        let rng = rng.clone();
        let general_params = general_params.clone();
        let pk = pk.clone();
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<
                _,
                MAX_NUM_ROW,
                MAX_CODESIZE_FOR_CALL_TRACE,
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
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        println!("proof length: {}", proof.len());

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
        .expect("failed to verify bench circuit");
    }

    group.bench_function("create proof", |b| {
        b.iter(|| {
            let circuit = circuit.clone();
            let rng = rng.clone();
            let general_params = general_params.clone();
            let pk = pk.clone();
            // Create a proof
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                ChaChaRng,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                SuperCircuit<
                    _,
                    MAX_NUM_ROW,
                    MAX_CODESIZE_FOR_CALL_TRACE,
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
            .expect("proof generation should not fail");
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
