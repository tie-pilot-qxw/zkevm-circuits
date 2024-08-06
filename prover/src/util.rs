// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use chrono::Utc;
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{Circuit, VerifyingKey};
use halo2_proofs::SerdeFormat;
use log::LevelFilter;
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use std::fs;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Once;

use eth_types::geth_types::ChunkData;
use zkevm_circuits::util::preprocess_trace;

pub static LOGGER: Once = Once::new();

pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}

pub fn handler_chunk_data(chunk_data: ChunkData) -> ChunkData {
    let mut data = chunk_data.clone();

    for block in &mut data.blocks {
        for trace in &mut block.geth_traces {
            preprocess_trace(trace);
        }
    }

    data
}

pub fn serialize_vk(vk: &VerifyingKey<G1Affine>) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    vk.write(&mut result, SerdeFormat::RawBytes).unwrap();
    result
}

pub fn deserialize_vk<C: Circuit<Fr>>(raw_vk: &[u8], params: C::Params) -> VerifyingKey<G1Affine> {
    VerifyingKey::<G1Affine>::read::<_, C>(
        &mut BufReader::new(raw_vk),
        SerdeFormat::RawBytes,
        params,
    )
    .unwrap()
}

pub fn serialize_instances(instances: Vec<Vec<Fr>>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for instance in instances {
        // 序列化单个实例并获取字节
        let instance_bytes = serialize_instance(instance);
        // 首先写入长度（使用固定字节数来存储长度，例如 4 个字节的 u32）
        let length = instance_bytes.len() as u32;
        bytes.extend_from_slice(&length.to_le_bytes());
        // 然后写入实例数据
        bytes.extend(instance_bytes);
    }
    bytes
}

fn serialize_instance(instance: Vec<Fr>) -> Vec<u8> {
    instance.iter().flat_map(|fr| serialize_fr(fr)).collect()
}

pub fn serialize_fr(f: &Fr) -> Vec<u8> {
    f.to_bytes().to_vec()
}

fn create_output_dir(id: &str) -> String {
    let mode = read_env_var("MODE", "multi".to_string());
    let output = read_env_var(
        "OUTPUT_DIR",
        format!(
            "{}_output_{}_{}",
            id,
            mode,
            Utc::now().format("%Y%m%d_%H%M%S")
        ),
    );

    let output_dir = PathBuf::from_str(&output).unwrap();
    fs::create_dir_all(output_dir).unwrap();

    output
}
pub fn init_env_and_log(id: &str) -> String {
    dotenvy::dotenv().ok();
    let output_dir = create_output_dir(id);

    LOGGER.call_once(|| {
        // TODO: cannot support complicated `RUST_LOG` for now.
        let log_level = read_env_var("RUST_LOG", "INFO".to_string());
        let log_level = LevelFilter::from_str(&log_level).unwrap_or(LevelFilter::Info);

        let mut log_file_path = PathBuf::from(output_dir.clone());
        log_file_path.push("log.txt");
        let log_file = FileAppender::builder().build(log_file_path).unwrap();

        let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

        let config = Config::builder()
            .appenders([
                Appender::builder().build("log-file", Box::new(log_file)),
                Appender::builder().build("stderr", Box::new(stderr)),
            ])
            .build(
                Root::builder()
                    .appender("log-file")
                    .appender("stderr")
                    .build(log_level),
            )
            .unwrap();

        log4rs::init_config(config).unwrap();
    });

    output_dir
}
