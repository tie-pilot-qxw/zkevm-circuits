use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, iter};

use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::{keygen_vk, JitProverEnv};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use itertools::Itertools;
use serde_json::to_writer;
use snark_verifier::halo2_base::gates::circuit::CircuitBuilderStage;
use snark_verifier::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::halo2::aggregation::{
    AggregationCircuit, AggregationConfigParams, VerifierUniversality,
};
use snark_verifier_sdk::halo2::gen_snark_shplonk;
use snark_verifier_sdk::{gen_pk, CircuitExt, Snark, SHPLONK};

use zkevm_circuits::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_chunk_data, SubCircuit};
use zkevm_circuits::witness::Witness;

fn gen_application_snark(
    params: &ParamsKZG<Bn256>,
    snark_pk_path: &PathBuf,
    snark_path: &PathBuf,
    env_info: &mut Option<JitProverEnv>,
) -> Snark {
    #[cfg(feature = "sstorage-circuit")]
    let chunk_data = &get_chunk_data(
        "../zkevm/zkevm-circuits/test_data/sstore_with_original/trace/block_info.json",
        "../zkevm/zkevm-circuits/test_data/sstore_with_original/trace/tx_info.json",
        "../zkevm/zkevm-circuits/test_data/sstore_with_original/trace/second_invoke.json",
        "../zkevm/zkevm-circuits/test_data/sstore_with_original/trace/tx_receipt.json",
        "../zkevm/zkevm-circuits/test_data/sstore_with_original/trace/bytecode.json",
    );
    #[cfg(feature = "call-trace-circuit")]
    let chunk_data = &get_chunk_data(
        "../zkevm/zkevm-circuits/test_data/call_test/trace/block_info.json",
        "../zkevm/zkevm-circuits/test_data/call_test/trace/tx_info.json",
        "../zkevm/zkevm-circuits/test_data/call_test/trace/tx_debug_trace.json",
        "../zkevm/zkevm-circuits/test_data/call_test/trace/tx_receipt.json",
        "../zkevm/zkevm-circuits/test_data/call_test/trace/bytecode.json",
    );
    #[cfg(feature = "erc20-deploy-circuit")]
    let chunk_data = &get_chunk_data(
        "../zkevm/zkevm-circuits/test_data/erc20_test/trace/t01_a_deploy_erc20/block_info.json",
        "../zkevm/zkevm-circuits/test_data/erc20_test/trace/t01_a_deploy_erc20/tx_info.json",
        "../zkevm/zkevm-circuits/test_data/erc20_test/trace/t01_a_deploy_erc20/tx_debug_trace.json",
        "../zkevm/zkevm-circuits/test_data/erc20_test/trace/t01_a_deploy_erc20/tx_receipt.json",
        "../zkevm/zkevm-circuits/test_data/erc20_test/trace/t01_a_deploy_erc20/bytecode.json",
    );
    let witness = Witness::new(chunk_data);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    // let mut witness_path = snark_path.to_path_buf();
    // let time = format!(
    //     "{}",
    //     SystemTime::now()
    //         .duration_since(UNIX_EPOCH)
    //         .expect("Time went backwards")
    //         .as_secs()
    // );
    // witness_path.push(format!("{}_witness.html", time));
    // let mut buf = std::io::BufWriter::new(File::create(witness_path).unwrap());
    // witness.write_html(&mut buf);
    let pk = gen_pk(params, &circuit, Some(snark_pk_path));
    // todo 从chunkdata中获取一些关于chunk的唯一性的信息来设值snark的临时存储路径,暂时用chunk中最后一个块的块号和hash串起来作唯一值
    let time = format!(
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    );

    let mut snark_storage_path = snark_path.to_path_buf();
    snark_storage_path.push(format!("{}.snark", time));
    // 若snark_storage_path存在则从已经序列化后的snark中加载,否则生成snark并序列化到指定的该路径下面(方便二次加载)
    gen_snark_shplonk(params, &pk, circuit, Some(&snark_storage_path), env_info)
}

fn set_path() {
    let exe_path = env::current_exe().expect("Failed to get current executable path");
    let mut project_dir = exe_path.to_path_buf();
    while !project_dir.join("Cargo.toml").exists() {
        project_dir = project_dir
            .parent()
            .expect("Failed to get parent directory")
            .to_path_buf();
    }
    env::set_current_dir(&project_dir)
        .expect("Failed to set current directory to project directory");
}

fn serialize_instance<F>(instances: &[Vec<F>]) -> Vec<u8>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    iter::empty()
        .chain(
            instances
                .iter()
                .flatten()
                .flat_map(|value: &F| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .collect()
}

fn write_proof_and_instances(
    proof: &Vec<u8>,
    instances: &Vec<Vec<Fr>>,
    prefix: String,
    snarks: &[Snark],
) {
    // get time
    let time = format!(
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    );

    // write proof to file
    let mut proof_file = File::create(format!("tmp_data/{}/{}_proof_{}", prefix, prefix, time))
        .expect("Unable to create proof_file");
    proof_file.write_all(proof).expect("Unable to write proof");

    // write instances to file
    let mut instances_file =
        File::create(format!("tmp_data/{}/{}_instances_{}", prefix, prefix, time))
            .expect("Unable to create instances_file");
    let serialized_instances = serialize_instance(instances);
    instances_file
        .write_all(&serialized_instances)
        .expect("Unable to write instances");

    // write snarks instances to file
    for (index, snark) in snarks.iter().enumerate() {
        let serialized_instances = serialize_instance(&snark.instances);
        let mut file = File::create(format!(
            "tmp_data/{}/{}_snarks_instance_{}_{}",
            prefix, prefix, index, time
        ))
        .expect("Unable to create snarks instance file");
        file.write_all(&serialized_instances)
            .expect("Unable to write snarks instance");

        let _file = File::create(format!(
            "tmp_data/{}/{}_snarks_instance_{}_{}.json",
            prefix, prefix, index, time
        ))
        .expect("Unable to create snarks instance file");
        to_writer(&_file, &snark.instances).expect("Unable to write snarks_instance.json");
    }

    let src_path = "aggregate-zkevm/BatchZkevmVerifier.sol";
    let dst_path = format!("tmp_data/{}/{}_code_{}.sol", prefix, prefix, time);
    if let Err(e) = fs::copy(src_path, dst_path) {
        eprintln!("Failed to copy code_file: {}", e);
    }
}

pub fn ensure_path_exists<P: AsRef<Path> + AsRef<std::ffi::OsStr>>(p: &P) -> String {
    let path = Path::new(p);
    if !path.exists() {
        fs::create_dir_all(path).unwrap();
    }
    path.to_str().unwrap().to_string()
}

fn main() {
    println!("MAX_NUM_ROWS:{}", MAX_NUM_ROW);

    set_path();
    // 设值srs存储路径
    let work_path = env::current_dir().unwrap();
    let srs_path = work_path.join("srs");
    ensure_path_exists(&srs_path);
    // 设值snark-pk和agg-pk的存储路径
    let pks_path = work_path.join("pks");
    ensure_path_exists(&pks_path);
    // 设值临时存储snark的路径
    let snarks_path = work_path.join("snarks");
    ensure_path_exists(&snarks_path);

    let snark_pk_path = pks_path.join("snark_pk");

    let agg_pk_path = pks_path.join("agg_pk");

    unsafe {
        env::set_var("PARAMS_DIR", srs_path.to_str().unwrap());
    }
    // 设值snark pk的存储路径
    // 设值aggregate pk的存储路径
    let degree = 19;

    // get prefix
    let prefix = "simple_opcode".to_string();
    #[cfg(feature = "call-trace-circuit")]
    let prefix = "call_trace".to_string();
    #[cfg(feature = "erc20-deploy-circuit")]
    let prefix = "erc20_deploy".to_string();
    #[cfg(feature = "sstorage-circuit")]
    let prefix = "sstorage".to_string();
    let k = 25u32;
    let lookup_bits = k as usize - 1;
    let srs_timer = start_timer!(|| "Generating SRS");

    let params = gen_srs(k);
    let mut params_app = params.clone();
    params_app.downsize(degree);

    end_timer!(srs_timer);
    let snark_timer = start_timer!(|| "Generating snark");
    todo!("use gpu");
    let snarks = [(); 1].map(|_| gen_application_snark(&params_app, &snark_pk_path, &snarks_path, &mut None));
    end_timer!(snark_timer);
    let agg_time = start_timer!(|| "Generating agg proof ");
    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {
            degree: k,
            lookup_bits,
            ..Default::default()
        },
        &params,
        snarks.clone(),
        VerifierUniversality::None,
    );
    let agg_config = agg_circuit.calculate_params(Some(20));

    let pk = gen_pk::<AggregationCircuit>(&params, &agg_circuit, Some(&agg_pk_path));

    // TODO https://github.com/axiom-crypto/snark-verifier/issues/25 ,后期bug修复,去除
    //  因当前axiom在加载pk的时候会丢失break point的bug存在,所以这里调用了一次keygen_vk来生成break_points信息
    let vk_time = start_timer!(|| "Generating vkey ");
    keygen_vk(&params, &agg_circuit).unwrap();
    end_timer!(vk_time);

    let break_points = agg_circuit.break_points();
    drop(agg_circuit);

    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        agg_config,
        &params,
        snarks.clone(),
        VerifierUniversality::None,
    )
    .use_break_points(break_points.clone());

    let mut _agg_circuit = agg_circuit.clone();
    _agg_circuit.expose_previous_instances(false);
    let _num_instances = _agg_circuit.num_instance();
    let _instances = _agg_circuit.instances();
    todo!("use gpu");
    let _proof = gen_evm_proof_shplonk(&params, &pk, _agg_circuit, _instances.clone(), &mut None);
    end_timer!(agg_time);
    let _deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        &params,
        pk.get_vk(),
        _num_instances,
        Some(Path::new("aggregate-zkevm/BatchZkevmVerifier.sol")),
    );

    let file = File::create("./evm_verifier.bin");
    file.unwrap().write_all(&_deployment_code).unwrap();

    write_proof_and_instances(&_proof, &_instances, prefix, &snarks);

    // #[cfg(feature = "revm")]
    // evm_verify(_deployment_code, _instances, _proof);
}
