// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::{rename, File};
use std::io::{BufReader, Write};
use std::path::Path;

use anyhow::Result;
use ark_std::rand::rngs::OsRng;
use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use snark_verifier_sdk::evm::{encode_calldata, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::halo2::aggregation::{
    AggregationCircuit, AggregationConfigParams, VerifierUniversality,
};
use snark_verifier_sdk::halo2::gen_snark_shplonk;
use snark_verifier_sdk::snark_verifier::halo2_base::gates::circuit::CircuitBuilderStage;
use snark_verifier_sdk::{gen_pk, CircuitExt, SHPLONK};

use eth_types::geth_types::ChunkData;
use trace_parser::trace_program;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{log2_ceil, SubCircuit};
use zkevm_circuits::witness::Witness;

use crate::constants::{
    AGG_DEGREE_FOR_TEST, AGG_PARAMS_FILENAME, AGG_PK_FILENAME, AGG_VK_FILENAME,
    CHUNK_PARAMS_FILENAME, CHUNK_PROTOCOL_FILENAME, CHUNK_VK_FILENAME, DEFAULT_PROOF_PARAMS_DIR,
    DEPLOYMENT_CODE_FILENAME, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
};
use crate::proof::chunk::ChunkProof;
use crate::test::proof_test::{
    get_default_chunk_trace_json, get_default_proof_params_file_path,
    get_default_proof_vk_file_path, write_proof_params, write_proof_vk,
};
use crate::util::handler_chunk_data;

/// 默认运行test时为fast_test, zkevm degree == 15, agg degree == 19
/// not fast_test, zkevm degree == 19, agg degree == 25，正式环境使用
#[test]
fn create_all_file() {
    complete_process(true);
    move_file().unwrap()
}
pub fn complete_process(need_gen_batch_proof: bool) {
    let (agg_params, zkevm_params, agg_degree, zkevm_degree) = generate_params();

    // 这里我们直接使用sstore的这个trace生成后续所需要的文件即可，在一个正确的电路里，witness不影响vk和pk的生成
    let zkevm_key_time = start_timer!(|| "generate and write key file");
    let file = File::open(get_default_chunk_trace_json(None)).expect("file should exist");
    let reader = BufReader::new(file);
    let chunk_data: ChunkData = serde_json::from_reader(reader).unwrap();
    let chunk_data = handler_chunk_data(chunk_data);

    // 构造zkevm电路
    let witness = Witness::new(&chunk_data);
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);

    let vk = keygen_vk(&zkevm_params, &circuit).unwrap();
    // 3.写入zkevm的vk
    write_proof_vk(&vk, get_default_proof_vk_file_path(zkevm_degree));

    // zkevm的pk不需要写入文件中，我们初始化不会读，会在生成proof的时候构造一次，之后存于内存
    let pk = keygen_pk(&zkevm_params, vk, &circuit).unwrap();
    end_timer!(zkevm_key_time);

    // 生成snark, 后面这个路径是把snark写入本地，我们初始化不需要这个文件，所以暂时可以选择不写入
    let snark_time = start_timer!(|| "generate snark and write protocol");
    let snark = gen_snark_shplonk(&zkevm_params, &pk, circuit, None::<String>);
    let chunk_proof = ChunkProof::new(snark.clone(), Some(&pk));
    // 4. 导出protocol及proof json
    chunk_proof
        .unwrap()
        .dump(
            DEFAULT_PROOF_PARAMS_DIR,
            format!("k{}", zkevm_degree).as_str(),
        )
        .unwrap();
    end_timer!(snark_time);

    // 构造聚合电路
    let agg_circuit_time = start_timer!(|| "generate agg_circuit");
    let lookup_bits = agg_degree as usize - 1;
    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {
            degree: agg_degree,
            lookup_bits,
            ..Default::default()
        },
        &agg_params,
        vec![snark.clone()],
        VerifierUniversality::None,
    );
    let agg_config = agg_circuit.calculate_params(Some(20));
    end_timer!(agg_circuit_time);

    // 5.写入agg_k25.pk文件，这个文件大概42GB左右，写入时注意磁盘空间，在测试中生成文件后，可以大大减少后面主程序生成时间
    // 在生成的同时，会直接写入文件
    let agg_key_time = start_timer!(|| "generate agg key and write to file");
    let pk = gen_pk(
        &agg_params,
        &agg_circuit,
        Some(Path::new(&format!(
            "{}/{}",
            DEFAULT_PROOF_PARAMS_DIR, *AGG_PK_FILENAME
        ))),
    );
    // 6.写入agg_k25.vk
    // 由于这里不会写入vk，我们可以主动写入一次，因为初始化我们需要这个
    write_proof_vk(
        pk.get_vk(),
        format!("{}/{}", DEFAULT_PROOF_PARAMS_DIR, *AGG_VK_FILENAME),
    );
    end_timer!(agg_key_time);

    // 这是遗留的一个开源bug，必须调用一次
    let bug_vk_time = start_timer!(|| "must call keygen_vk");
    keygen_vk(&agg_params, &agg_circuit).unwrap();
    end_timer!(bug_vk_time);

    let deployment_code_time = start_timer!(|| "generate and write deployment code");
    let break_points = agg_circuit.break_points();
    drop(agg_circuit);
    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        agg_config,
        &agg_params,
        vec![snark],
        VerifierUniversality::None,
    )
    .use_break_points(break_points.clone());

    let mut agg_circuit = agg_circuit.clone();
    agg_circuit.expose_previous_instances(false);

    // 7.写入合约字节码
    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        &agg_params,
        pk.get_vk(),
        agg_circuit.num_instance(),
        Some(Path::new("./test_data/BatchZkevmVerifier.sol")),
    );

    let file = File::create("./test_data/evm_verifier.bin");
    file.unwrap().write_all(&deployment_code).unwrap();
    end_timer!(deployment_code_time);

    if need_gen_batch_proof {
        let proof_time = start_timer!(|| "generate proof");
        let instances = agg_circuit.instances();
        let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit.clone(), instances.clone());
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "verify proof");
        let call_data = encode_calldata(&instances, &proof);
        let trace = trace_program(&deployment_code, &call_data);
        println!("evm gas used: {}", trace.gas);
        assert!(!trace.failed);
        end_timer!(verify_time);
    }
}

fn generate_params() -> (ParamsKZG<Bn256>, ParamsKZG<Bn256>, u32, u32) {
    // 按照之前测试，聚合电路的degree暂时设置为25
    let params_time = start_timer!(|| format!(
        "generate and write params, MAX_NUM_ROW:{}",
        MAX_NUM_ROW_FOR_TEST
    ));
    let agg_degree = AGG_DEGREE_FOR_TEST as u32;
    let filename = get_default_proof_params_file_path(agg_degree);
    let path = Path::new(filename.as_str());

    let agg_params = match path.exists() {
        true => {
            println!(
                "file {} exists, read file",
                format!("k{}.params", agg_degree)
            );
            let f = File::open(path).unwrap();
            let mut reader = BufReader::new(f);
            ParamsKZG::<Bn256>::read(&mut reader).unwrap()
        }
        false => {
            let params = ParamsKZG::<Bn256>::setup(agg_degree, OsRng);
            // 1.写入degree == 25的params
            write_proof_params(&params, get_default_proof_params_file_path(agg_degree));
            params
        }
    };

    // zkevm电路degree一般按照19生成
    let mut cs = ConstraintSystem::<Fr>::default();
    SuperCircuit::<Fr, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::configure(
        &mut cs,
    );
    let minimum_rows = cs.minimum_rows();
    let rows = MAX_NUM_ROW_FOR_TEST + minimum_rows;
    let zkevm_degree = log2_ceil(rows);

    let filename = get_default_proof_params_file_path(zkevm_degree);
    let path = Path::new(filename.as_str());
    let zkevm_params = match path.exists() {
        true => {
            println!(
                "file {} exists, read file",
                format!("k{}.params", zkevm_degree)
            );
            let f = File::open(path).unwrap();
            let mut reader = BufReader::new(f);
            ParamsKZG::<Bn256>::read(&mut reader).unwrap()
        }
        false => {
            let mut zkevm_params = agg_params.clone();
            zkevm_params.downsize(zkevm_degree);
            // 2.写入degree == 19的params
            write_proof_params(
                &zkevm_params,
                get_default_proof_params_file_path(zkevm_degree),
            );
            zkevm_params
        }
    };
    end_timer!(params_time);

    (agg_params, zkevm_params, agg_degree, zkevm_degree)
}

fn move_file() -> Result<()> {
    // 设定源目录和目标目录
    let src_dir = DEFAULT_PROOF_PARAMS_DIR;
    let assets_dir = format!("{}/{}", DEFAULT_PROOF_PARAMS_DIR, "assets");
    let params_dir = format!("{}/{}", DEFAULT_PROOF_PARAMS_DIR, "params");

    // 创建目标目录，如果它们不存在
    fs::create_dir_all(assets_dir.clone())?;
    fs::create_dir_all(params_dir.clone())?;

    // 1.移动文件 k25.params 到 params_dir 目录
    rename_file(src_dir, params_dir.as_str(), AGG_PARAMS_FILENAME.as_str())?;

    // 2.移动文件 k19.params 到 params_dir 目录
    rename_file(src_dir, params_dir.as_str(), CHUNK_PARAMS_FILENAME.as_str())?;

    // 3.移动文件 agg_k25.vk 到 assets 目录
    rename_file(src_dir, assets_dir.as_str(), AGG_VK_FILENAME.as_str())?;

    // 4.移动文件 agg_k25.pk 到 assets 目录
    rename_file(src_dir, assets_dir.as_str(), AGG_PK_FILENAME.as_str())?;

    // 5.移动文件 chunk.protocol 到 assets 目录
    rename_file(
        src_dir,
        assets_dir.as_str(),
        CHUNK_PROTOCOL_FILENAME.as_str(),
    )?;

    // 6.移动文件 k15.vk 到 assets 目录
    rename_file(src_dir, assets_dir.as_str(), CHUNK_VK_FILENAME.as_str())?;

    // 7.移动文件 evm_verifier.bin 到 assets 目录
    rename_file(
        src_dir,
        assets_dir.as_str(),
        DEPLOYMENT_CODE_FILENAME.as_str(),
    )?;

    println!("Files have been moved successfully.");
    Ok(())
}

fn rename_file(src_dir: &str, dst_dir: &str, file_name: &str) -> Result<()> {
    let src_file = format!("{}/{}", src_dir, file_name);
    let dest_file = format!("{}/{}", dst_dir, file_name);
    rename(&src_file, &dest_file)?;
    Ok(())
}
