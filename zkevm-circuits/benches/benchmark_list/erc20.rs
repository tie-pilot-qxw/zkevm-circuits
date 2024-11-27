// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::run_benchmark;
use zkevm_circuits::util::get_chunk_data;

#[cfg(feature = "k_11")]
const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = 21000;

#[cfg(feature = "k_11")]
const CALL_MAX_NUM_ROW_FOR_TEST: usize = 6000;

#[cfg(not(feature = "k_11"))]
const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = MAX_NUM_ROW;

#[cfg(not(feature = "k_11"))]
const CALL_MAX_NUM_ROW_FOR_TEST: usize = MAX_NUM_ROW;

#[test]
fn t01_a_deploy_erc20() {
    let chunk_data = &get_chunk_data(
        "test_data/erc20_test/trace/t01_a_deploy_erc20/block_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_debug_trace.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_receipt.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/bytecode.json",
    );

    let degree: u32 = 15;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<DEPLOY_MAX_NUM_ROW_FOR_TEST>("t01_a_deploy_erc20", chunk_data, degree);
}
#[test]
fn t02_a_transfer_b_200() {
    let chunk_data = &get_chunk_data(
        "test_data/erc20_test/trace/t02_a_transfer_b_200/block_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST>("t02_a_transfer_b_200", chunk_data, degree);
}

#[test]
fn t03_a_approve_c_200() {
    let chunk_data = &get_chunk_data(
        "test_data/erc20_test/trace/t03_a_approve_c_200/block_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_receipt.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST>("t03_a_approve_c_200", chunk_data, degree);
}

#[test]
fn t04_c_transfer_from_a_b_200() {
    let chunk_data = &get_chunk_data(
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/block_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST>(
        "t04_c_transfer_from_a_b_200 benchmark",
        chunk_data,
        degree,
    );
}
