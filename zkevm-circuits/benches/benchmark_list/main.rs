// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

mod call_trace;
mod super_circuit;

mod erc20;
mod init_proof_params;

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ark_std::{end_timer, start_timer};
use eth_types::geth_types::ChunkData;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{
    gen as prover_gen, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
use halo2_proofs::zkpoly_compiler::driver;
use halo2_proofs::zkpoly_compiler::driver::artifect::Pools;
use halo2_proofs::zkpoly_compiler::driver::{DiskMemoryInfo, MemoryInfo};
use halo2_proofs::zkpoly_runtime::debug::statistics::Statistics;
use halo2_proofs::SerdeFormat;
use rand_chacha::rand_core::OsRng;
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

pub fn run_benchmark<const MAX_NUM_ROW: usize>(
    id: &str,
    chunk_data: &ChunkData,
    degree: u32,
) -> (std::time::Duration, Option<Statistics>) {
    let config = driver::Config::default()
        .with_sliceable_subgraph_on(
            driver::SubgraphSlicingConfig::default()
                .with_chunk_len(2u64.pow((degree - 3).max(17)))
                .with_minimum_order(10),
        )
        .with_scheduler_alg(driver::GraphSchedulingAlgorithm::KillAsap)
        .with_memory_planning(
            driver::MemoryPlanningConfig::default()
                .with_smithereen_space(2u64.pow(28))
                .with_gpu_allocator(driver::GpuAllocatorChoice::Page(128 * 2u64.pow(20)))
                .with_criterion(driver::CriterionChoice::Belady),
        )
        .with_arith_graph_scheduler(driver::ArithGraphSchedulerChoice::Heuristic);

    let cpu_capacity = (200 * 2u64.pow(degree - 19)).min(400);
    let hd_info = driver::HardwareInfo::new(MemoryInfo::new(cpu_capacity * 2u64.pow(30)))
        .with_gpu(MemoryInfo::new(28 * 2u64.pow(30)))
        .with_disk(DiskMemoryInfo::new(Some(PathBuf::from("/data/tmp"))));

    let record_log: bool = env::var("RECORD_LOG").is_ok_and(|x| x == "1");

    let options = driver::DebugOptions::minimal("target/debug/transit".into())
        .with_type2_visualizer(driver::Type2DebugVisualizer::Cytoscape)
        .with_log(true);
    options.prepare_dir();

    run_benchmark_with_config::<MAX_NUM_ROW>(
        id,
        chunk_data,
        degree,
        &hd_info,
        &options,
        &config,
        record_log,
        PathBuf::from("target/kernels"),
    )
}

pub fn run_benchmark_with_config<const MAX_NUM_ROW: usize>(
    id: &str,
    chunk_data: &ChunkData,
    degree: u32,
    hd_info: &driver::HardwareInfo,
    options: &driver::DebugOptions,
    config: &driver::Config,
    record_log: bool,
    kernel_dir: PathBuf,
) -> (std::time::Duration, Option<Statistics>) {
    // get round from environment variables
    let round_val_str = env::var(CMD_ENV_ROUND).unwrap_or_else(|_| "".to_string());
    let bench_round: usize = round_val_str
        .parse()
        .unwrap_or_else(|_| DEFAULT_BENCH_ROUND);

    let usefile_val_str = env::var(CMD_ENV_USEFILE).unwrap_or_else(|_| "".to_string());
    let bench_usefile: bool = usefile_val_str
        .parse()
        .unwrap_or_else(|_| DEFAULT_BENCH_USEFILE);
    let rebuild: bool = env::var("REBUILD").is_ok_and(|x| x == "1");
    let trace_reference_run: bool = env::var("ASSERT").is_ok_and(|x| x == "1");
    let dump: bool = env::var("dump").is_ok_and(|x| x == "1");

    println!(
        "{}/id:{}, max_num_row:{}, degree:{}, round:{}, use params file:{}, rebuild: {}, record runtime log: {}, trace reference run: {}",
        CIRCUIT_SUMMARY, id, MAX_NUM_ROW, degree, bench_round, bench_usefile, rebuild, record_log, trace_reference_run
    );

    // step1: get proof params
    let get_proof_params_start = start_timer!(|| "get proof params");
    let params_path = get_default_proof_params_file_path(degree);
    let pk_path = get_default_proof_pk_file_path(degree);
    let (proof_params, proof_pk) = if bench_usefile
        && PathBuf::from(&params_path).exists()
        && PathBuf::from(&pk_path).exists()
    {
        get_proof_params_from_file::<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
            params_path,
            get_default_proof_vk_file_path(degree),
            pk_path,
        )
    } else {
        let witness = Witness::new(chunk_data);
        let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
            SuperCircuit::new_from_witness(&witness);
        gen_proof_params_and_write_file(degree, circuit)
    };
    end_timer!(get_proof_params_start);

    println!("{}/id:{}, config: {:#?}", CIRCUIT_SUMMARY, id, config);
    println!(
        "{}/id:{}, debug_dir: {:?}, kernel_dir: {:?}",
        CIRCUIT_SUMMARY,
        id,
        &options.debug_dir(),
        &kernel_dir
    );

    // step2: run and verify circuit
    let run_and_verify_circuit_start = start_timer!(|| "run and verify circuit");
    let r = run_circuit::<MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
        id,
        chunk_data,
        bench_round,
        proof_params,
        proof_pk,
        &hd_info,
        options,
        &config,
        rebuild,
        record_log,
        trace_reference_run,
        kernel_dir,
        dump,
    );
    end_timer!(run_and_verify_circuit_start);

    r
}

fn gen_proof_params_and_write_file<const MAX_NUM_ROW: usize>(
    degree: u32,
    circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    println!(
        "{}/max_num_row:{}, degree:{}",
        CIRCUIT_SUMMARY, MAX_NUM_ROW, degree
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

    (proof_params, pk)
}

fn get_proof_params_from_file<
    const MAX_NUM_ROW: usize,
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
    // 	NUM_STATE_HI_COL,
    // 	NUM_STATE_LO_COL>(proof_vk_file_path);
    // end_timer!(read_proof_vk_start);

    let read_proof_pk_start = start_timer!(|| format!("read proof pk form {}", proof_pk_file_path));
    let proof_pk = read_proof_pk_from_file::<_, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>(
        proof_pk_file_path,
    );
    end_timer!(read_proof_pk_start);

    (proof_params, proof_pk)
}

fn _gen_proof_params<
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    degree: u32,
    chunk_data: &ChunkData,
) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    let witness = Witness::new(chunk_data);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
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

pub fn run_circuit<
    const MAX_NUM_ROW: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>(
    id: &str,
    chunk_data: &ChunkData,
    bench_round: usize,
    proof_params: ParamsKZG<Bn256>,
    proof_pk: ProvingKey<G1Affine>,
    hd_info: &driver::HardwareInfo,
    options: &driver::DebugOptions,
    config: &driver::Config,
    rebuild: bool,
    record_log: bool,
    trace_reference_run: bool,
    kernel_dir: PathBuf,
    dump: bool,
) -> (std::time::Duration, Option<Statistics>) {
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
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance: Vec<Vec<Fr>> = circuit.instance();
    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
    end_timer!(circuit_start);

    // create proof and verify
    let i = 0;
    println!("cloning circuit for round {}", i + 1);
    let circuit = circuit;
    println!("cloning instance_refs for round {}", i + 1);
    let general_params = proof_params;
    println!("cloning proof_pk for round {}", i + 1);
    let pk = proof_pk;

    // Create a proof
    let proof_msg = format!(
        "{}/{}/Create proof/Round {}/{}",
        CREATE_PROOF,
        id,
        i + 1,
        bench_round
    );

    println!("allcator create for round {}", i + 1);
    let allocator =
        halo2_proofs::zkpoly_memory_pool::CpuMemoryPool::new(32, std::mem::size_of::<u32>());

    let mut trace = halo2_proofs::tracing::Trace::default();

    let trace = if trace_reference_run {
        println!("extended k = {}", pk.get_vk().get_domain().extended_k());

        let trace_start = start_timer!(|| "[Test] Begin Running Original Prover for Trace");
        let _proof = {
            use halo2_proofs::transcript::TranscriptWriterBuffer;
            let mut transcript = halo2_proofs::transcript::Blake2bWrite::<
                _,
                _,
                halo2_proofs::transcript::Challenge255<G1Affine>,
            >::init(vec![]);
            halo2_proofs::plonk::create_proof_traced::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<Bn256>,
                _,
                _,
                _,
                _,
            >(
                &general_params,
                &pk,
                &[circuit.clone()],
                &[&instance_refs],
                OsRng,
                &mut transcript,
                Some(&mut trace),
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        };
        end_timer!(trace_start);
        Some(&trace)
    } else {
        None
    };

    type E = halo2_proofs::zkpoly_runtime::transcript::Challenge255<G1Affine>;
    type Tr = halo2_proofs::zkpoly_runtime::transcript::Blake2bWrite<Vec<u8>, G1Affine, E>;

    let disk_constant_allocator = hd_info.disk_allocator(16 * 2usize.pow(30));
    let mut constant_pool = driver::ConstantPool::with_disk(allocator, disk_constant_allocator);

    let instance_lengths = vec![instance_refs
        .iter()
        .map(|ins| ins.len())
        .collect::<Vec<usize>>()];

    let (artifect, cg_inputs_shape) = std::thread::scope(|s| {
        let handler = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn_scoped(s, || {
                let cg_gen_start = start_timer!(|| proof_msg);
                let (cg_ret, cg_inputs_shape) = prover_gen::create_proof_validated::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<Bn256>,
                    E,
                    Tr,
                    _,
                >(
                    &general_params,
                    &pk,
                    &[circuit.clone()],
                    &instance_lengths,
                    &mut constant_pool,
                    trace,
                );
                end_timer!(cg_gen_start);

                let compile_start = start_timer!(|| "[Test] Compiling to Runtime Instructions");
                let artifect_dir = "target/artifect";
                let processed_type2_dir = "target/processed_type2";
                let fresh_type2 = driver::FreshType2::from_ast(cg_ret, &options).unwrap();
                let mut str_buf = Vec::new();

                let artifect = if rebuild || !std::path::Path::new(artifect_dir).exists() {
                    let processed_type2 =
                        if !rebuild && std::path::Path::new(processed_type2_dir).exists() {
                            println!("[Test] Loading dumped processed Type2");
                            fresh_type2
                                .load_processed_type2(
                                    &processed_type2_dir,
                                    &mut str_buf,
                                    &mut constant_pool,
                                    &config,
                                    &hd_info,
                                    &options,
                                )
                                .unwrap()
                        } else {
                            println!("[Test] Applying Type2 passes and lowering to Artifect");
                            let pt2 = fresh_type2
                                .apply_passes(&hd_info, &mut constant_pool, &config)
                                .unwrap()
                                .fuse(0..1)
                                .unwrap();
                            if dump {
                                pt2.dump(&processed_type2_dir, &mut constant_pool).unwrap();
                            }
                            pt2
                        };

                    let artifect = processed_type2
                        .to_type3(&mut constant_pool)
                        .unwrap()
                        .apply_passes()
                        .unwrap()
                        .to_artifect(kernel_dir)
                        .unwrap();

                    if dump {
                        artifect.dump(&artifect_dir, &mut constant_pool).unwrap();
                    }
                    artifect.finish(&mut constant_pool)
                } else {
                    println!("[Test] Loading dumped artifect");
                    fresh_type2
                        .load_artifect(&artifect_dir, &mut constant_pool)
                        .unwrap()
                };

                end_timer!(compile_start);

                (artifect, cg_inputs_shape)
            })
            .unwrap();

        handler.join().unwrap()
    });

    use halo2_proofs::zkpoly_runtime::transcript::TranscriptWriterBuffer;
    let instances = instance_refs
        .iter()
        .map(|ins| {
            halo2_proofs::zkpoly_runtime::scalar::ScalarArray::from_vec(
                &ins,
                &mut constant_pool.cpu,
            )
        })
        .collect();
    let mut inputs = cg_inputs_shape.serialize(vec![instances], vec![circuit], Tr::init(vec![]));

    let pools = Pools {
        cpu: hd_info.cpu_allocator(true),
        gpu: hd_info.gpu_allocators(true, config.memory()),
        disk: Arc::new(Mutex::new(hd_info.disk_allocator(2usize.pow(33)))),
    };
    let mut runtime = artifect.prepare_dispatcher(
        artifect.versions().next().unwrap(),
        pools,
        halo2_proofs::zkpoly_runtime::async_rng::AsyncRng::new(2usize.pow(20), OsRng::default()),
        Arc::new(|_| 0),
    );

    let dispatcher_start = start_timer!(|| "[Test] Running Dispatcher");
    let ((r, log, _), allocator) = runtime.run(
        &mut inputs,
        halo2_proofs::zkpoly_runtime::runtime::RuntimeDebug::none()
            .with_serial_execution(false)
            .with_print_instruction(true)
            .with_record_time(record_log),
    );
    let proof_time = log.total_time();
    end_timer!(dispatcher_start);

    if record_log {
        let mut waterfall_file =
            File::create(options.debug_dir().join("debug-statistics.html")).unwrap();
        log.waterfall().build(&mut waterfall_file).unwrap();
    }

    let proof = r.unwrap().unwrap_transcript_move().take().finalize();

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

    match verify_proof::<
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
    ) {
        Ok(..) => {}
        Err(e) => println!("{}/failed to verify bench circuit: {:?}", id, e),
    };
    end_timer!(verify_start);

    drop(allocator);

    (
        proof_time,
        if record_log {
            Some(log.statistics())
        } else {
            None
        },
    )
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

pub fn get_default_proof_params_file_path(degree: u32) -> String {
    format!("{}/k{}.params", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_vk_file_path(degree: u32) -> String {
    format!("{}/k{}.vk", DEFAULT_PROOF_PARAMS_DIR, degree)
}

pub fn get_default_proof_pk_file_path(degree: u32) -> String {
    format!("{}/k{}.pk", DEFAULT_PROOF_PARAMS_DIR, degree)
}
