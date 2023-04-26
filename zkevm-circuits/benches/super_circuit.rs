//! benchmark create_proof for super_circuit
#[macro_use]
extern crate criterion;

use criterion::Criterion;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness::Block;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("create proof");
    group.sample_size(10);

    let machine_code = trace_parser::assemble_file("debug/1.txt");
    let trace = trace_parser::trace_program(&machine_code);
    let block: Block<Fr> = Block::new_from_code_trace(&machine_code, &trace);
    let circuit: SuperCircuit<Fr> = SuperCircuit::new_from_block(&block);
    let instance: Vec<Vec<Fr>> = vec![];
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

    let degree = 9;

    // Bench setup generation
    let mut rng = ChaChaRng::seed_from_u64(2);
    let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
    // Initialize the proving key
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");

    // print proof length
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
            SuperCircuit<Fr>,
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
                SuperCircuit<Fr>,
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
