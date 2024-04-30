use crate::{run_benchmark, DEFAULT_BENCH_ROUND};
use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW};
use zkevm_circuits::util::get_geth_data;

#[cfg(feature = "k_10")]
const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = 21000;
#[cfg(feature = "k_10")]
const DEPLOY_MAX_CODE_SIZE_FOR_TEST: usize = 7000;
#[cfg(feature = "k_10")]
const CALL_MAX_NUM_ROW_FOR_TEST: usize = 6000;
#[cfg(feature = "k_10")]
const CALL_MAX_CODE_SIZE_FOR_TEST: usize = 5000;

#[cfg(not(feature = "k_10"))]
const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = MAX_NUM_ROW;
#[cfg(not(feature = "k_10"))]
const DEPLOY_MAX_CODE_SIZE_FOR_TEST: usize = MAX_CODESIZE;
#[cfg(not(feature = "k_10"))]
const CALL_MAX_NUM_ROW_FOR_TEST: usize = MAX_NUM_ROW;
#[cfg(not(feature = "k_10"))]
const CALL_MAX_CODE_SIZE_FOR_TEST: usize = MAX_CODESIZE;

#[test]
fn t01_a_deploy_erc20() {
    let geth_data = &get_geth_data(
        "test_data/erc20_test/trace/t01_a_deploy_erc20/block_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_info.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_debug_trace.json",
        "test_data/erc20_test/trace/t01_a_deploy_erc20/tx_receipt.json",
        "test_data/erc20_test/trace/bytecode.json",
    );

    let degree: u32 = 15;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<DEPLOY_MAX_NUM_ROW_FOR_TEST, DEPLOY_MAX_CODE_SIZE_FOR_TEST>(
        "t01_a_deploy_erc20",
        geth_data,
        degree,
        DEFAULT_BENCH_ROUND,
    );
}
#[test]
fn t02_a_transfer_b_200() {
    let geth_data = &get_geth_data(
        "test_data/erc20_test/trace/t02_a_transfer_b_200/block_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST, CALL_MAX_CODE_SIZE_FOR_TEST>(
        "t02_a_transfer_b_200",
        geth_data,
        degree,
        DEFAULT_BENCH_ROUND,
    );
}

#[test]
fn t03_a_approve_c_200() {
    let geth_data = &get_geth_data(
        "test_data/erc20_test/trace/t03_a_approve_c_200/block_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_info.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t03_a_approve_c_200/tx_receipt.json",
        "test_data/erc20_test/trace/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST, CALL_MAX_CODE_SIZE_FOR_TEST>(
        "t03_a_approve_c_200",
        geth_data,
        degree,
        DEFAULT_BENCH_ROUND,
    );
}

#[test]
fn t04_c_transfer_from_a_b_200() {
    let geth_data = &get_geth_data(
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/block_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_info.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t04_c_transfer_from_a_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/bytecode.json",
    );

    let degree: u32 = 13;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    run_benchmark::<CALL_MAX_NUM_ROW_FOR_TEST, CALL_MAX_CODE_SIZE_FOR_TEST>(
        "t04_c_transfer_from_a_b_200 benchmark",
        geth_data,
        degree,
        DEFAULT_BENCH_ROUND,
    );
}
