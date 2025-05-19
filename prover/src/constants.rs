// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::util::read_env_var;
use once_cell::sync::Lazy;
// environment variables key
pub const CMD_ENV_ROUND: &str = "ROUND";
pub const CMD_ENV_USEFILE: &str = "USEFILE";
// default bench round
pub const DEFAULT_BENCH_ROUND: usize = 1;
pub const DEFAULT_BENCH_USEFILE: bool = false;
// circuit summary prefix, degree, max_num_row, round
pub const CIRCUIT_SUMMARY: &str = "[Circuit summary]";
// generate witness , gw
pub const GENERATE_WITNESS: &str = "[Generate witness]";
// create circuit ,cc
pub const CREATE_CIRCUIT: &str = "[Create circuit]";
// create proof ,cp
pub const DEFAULT_PROOF_PARAMS_DIR: &str = "./test_data";
// Recommended solc version
pub const RECOMMENDED_SOLC_VERSION: &str = "0.8.19";
// Recommended  evm version
pub const RECOMMENDED_EVM_VERSION: &str = "1.13.9";

#[cfg(feature = "fast_test")]
pub const MAX_NUM_ROW_FOR_TEST: usize = 21000;
#[cfg(not(feature = "fast_test"))]
pub const MAX_NUM_ROW_FOR_TEST: usize = 280000;

#[cfg(feature = "fast_test")]
pub const AGG_DEGREE_FOR_TEST: usize = 19;
#[cfg(not(feature = "fast_test"))]
pub const AGG_DEGREE_FOR_TEST: usize = 25;

pub const NUM_STATE_HI_COL: usize = 9;

pub const NUM_STATE_LO_COL: usize = 9;

#[cfg(not(feature = "fast_test"))]
const AGG_VK_FILENAME_CONST: &str = "agg_k25.vk";
#[cfg(feature = "fast_test")]
const AGG_VK_FILENAME_CONST: &str = "agg_k19.vk";

#[cfg(not(feature = "fast_test"))]
const AGG_PK_FILENAME_CONST: &str = "agg_k25.pk";
#[cfg(feature = "fast_test")]
const AGG_PK_FILENAME_CONST: &str = "agg_k19.pk";

#[cfg(not(feature = "fast_test"))]
const AGG_PARAMS_FILENAME_CONST: &str = "k25.params";
#[cfg(feature = "fast_test")]
const AGG_PARAMS_FILENAME_CONST: &str = "k19.params";

#[cfg(not(feature = "fast_test"))]
const CHUNK_PARAMS_FILENAME_CONST: &str = "k19.params";
#[cfg(feature = "fast_test")]
const CHUNK_PARAMS_FILENAME_CONST: &str = "k15.params";

#[cfg(not(feature = "fast_test"))]
const CHUNK_VK_FILENAME_CONST: &str = "k19.vk";
#[cfg(feature = "fast_test")]
const CHUNK_VK_FILENAME_CONST: &str = "k15.vk";

const CHUNK_PROTOCOL_FILENAME_CONST: &str = "chunk.protocol";

const DEPLOYMENT_CODE_FILENAME_CONST: &str = "evm_verifier.bin";

pub static AGG_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("AGG_VK_FILENAME", AGG_VK_FILENAME_CONST.to_string()));

pub static AGG_PK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("AGG_VK_FILENAME", AGG_PK_FILENAME_CONST.to_string()));

pub static AGG_PARAMS_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("AGG_PARAMS_FILENAME", AGG_PARAMS_FILENAME_CONST.to_string()));

pub static CHUNK_PARAMS_FILENAME: Lazy<String> = Lazy::new(|| {
    read_env_var(
        "AGG_PARAMS_FILENAME",
        CHUNK_PARAMS_FILENAME_CONST.to_string(),
    )
});
pub static CHUNK_PROTOCOL_FILENAME: Lazy<String> = Lazy::new(|| {
    read_env_var(
        "CHUNK_PROTOCOL_FILENAME",
        CHUNK_PROTOCOL_FILENAME_CONST.to_string(),
    )
});
pub static CHUNK_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("CHUNK_VK_FILENAME", CHUNK_VK_FILENAME_CONST.to_string()));

pub static DEPLOYMENT_CODE_FILENAME: Lazy<String> = Lazy::new(|| {
    read_env_var(
        "DEPLOYMENT_CODE_FILENAME",
        DEPLOYMENT_CODE_FILENAME_CONST.to_string(),
    )
});
