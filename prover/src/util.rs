// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Once;
use std::{fs, str};

use chrono::Utc;
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{Circuit, VerifyingKey};
use halo2_proofs::SerdeFormat;
use log::LevelFilter;
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;

use eth_types::geth_types::ChunkData;
use zkevm_circuits::util::preprocess_trace;

pub static LOGGER: Once = Once::new();
pub const GIT_VERSION: &str = env!("ZKEVM_GIT_VERSION");

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
    VerifyingKey::<G1Affine>::read::<_, C>(&mut Cursor::new(raw_vk), SerdeFormat::RawBytes, params)
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

/// 检查环境中 solc 是否为推荐版本
pub fn check_solc_version(expected_version: &str) -> Result<(), String> {
    // 运行 solc --version 命令获取当前版本
    let output = match std::process::Command::new("solc").arg("--version").output() {
        Ok(output) => output,
        Err(e) => {
            eprintln!(
                "\x1b[31m[ERROR] Failed to execute solc command: {}\x1b[0m",
                e
            ); // Red
            eprintln!(
                "\x1b[34mPlease reinstall solc, the recommended version is: {}.\x1b[0m",
                expected_version
            ); // Blue
            return Err(format!("Failed to execute solc command: {}", e));
        }
    };

    // 检查命令是否成功执行
    if !output.status.success() {
        eprintln!("\x1b[31m[ERROR] solc command execution failed\x1b[0m"); // Red
        eprintln!(
            "\x1b[34mPlease reinstall solc, the recommended version is: {}.\x1b[0m",
            expected_version
        ); // Blue
        return Err("solc command execution failed".to_string());
    }

    // 解析输出
    let version_str = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("\x1b[31m[ERROR] Failed to parse solc version output\x1b[0m"); // Red
            eprintln!(
                "\x1b[34mPlease reinstall solc, the recommended version is: {}.\x1b[0m",
                expected_version
            ); // Blue
            return Err("Failed to parse solc version output".to_string());
        }
    };

    // 解析版本号
    let version_flag = "Version: ";
    if let Some(version_line) = version_str
        .lines()
        .find(|line| line.starts_with(version_flag))
    {
        let current_version = version_line.trim_start_matches(version_flag);

        // 提取主要版本号
        let current_version_main = if let Some(idx) = current_version.find('+') {
            &current_version[0..idx]
        } else {
            current_version
        };

        if current_version_main.contains(expected_version)
            || current_version.contains(expected_version)
        {
            println!("\x1b[32m[SOLC] Version matched: {}\x1b[0m", current_version); // Green
            Ok(())
        } else {
            println!(
                "\x1b[33m[WARNING] solc version mismatch: expected {}, found {}\x1b[0m",
                expected_version, current_version
            ); // Yellow
            Ok(())
        }
    } else {
        eprintln!("\x1b[31m[ERROR] Failed to parse solc version from output\x1b[0m"); // Red
        eprintln!(
            "\x1b[34mPlease reinstall solc, the recommended version is: {}.\x1b[0m",
            expected_version
        ); // Blue
        Err("Failed to parse solc version from output".to_string())
    }
}

pub fn check_evm_file(expected_version: &str) -> Result<(), String> {
    let evm_path = PathBuf::from("evm");
    if !evm_path.exists() {
        eprintln!("\x1b[31m[ERROR] evm file not found in current directory\x1b[0m"); // Red
        eprintln!(
            "\x1b[34mPlease compile or download the evm binary (recommended version: {}) and place it in the prover folder.\x1b[0m",
            expected_version
        ); // Blue
        return Err("evm file not found in current directory".to_string());
    }

    let output = match std::process::Command::new("./evm")
        .arg("--version")
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!(
                "\x1b[31m[ERROR] Failed to execute evm command: {}\x1b[0m",
                e
            ); // Red
            eprintln!(
                "\x1b[34mPlease compile or download the evm binary (recommended version: {}) and place it in the prover folder.\x1b[0m",
                expected_version
            ); // Blue
            return Err(format!("Failed to execute evm command: {}", e));
        }
    };
    if !output.status.success() {
        eprintln!("\x1b[31m[ERROR] evm command execution failed\x1b[0m"); // Red
        eprintln!(
            "\x1b[34mPlease compile or download the evm binary (recommended version: {}) and place it in the prover folder.\x1b[0m",
            expected_version
        ); // Blue
        return Err("evm command execution failed".to_string());
    }
    let version_str = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("\x1b[31m[ERROR] Failed to parse evm version output\x1b[0m"); // Red
            eprintln!(
                "\x1b[34mPlease compile or download the evm binary (recommended version: {}) and place it in the prover folder.\x1b[0m",
                expected_version
            ); // Blue
            return Err("Failed to parse evm version output".to_string());
        }
    };
    // 解析版本号
    let version_flag = "version";
    if let Some(version_line) = version_str.lines().find(|line| line.contains(version_flag)) {
        let current_version = version_line.trim_start_matches(version_flag);
        if current_version.contains(expected_version) {
            println!("\x1b[32m[EVM] Version matched: {}\x1b[0m", current_version);
            Ok(())
        } else {
            println!(
                "\x1b[33m[WARNING] evm version mismatch: expected {}, found {}\x1b[0m",
                expected_version, current_version
            ); // Yellow
            Ok(())
        }
    } else {
        eprintln!("\x1b[31m[ERROR] Failed to parse evm version from output\x1b[0m"); // Red
        eprintln!(
            "\x1b[34mPlease compile or download the evm binary (recommended version: {}) and place it in the prover folder.\x1b[0m",
            expected_version
        ); // Blue
        Err("Failed to parse evm version from output".to_string())
    }
}
