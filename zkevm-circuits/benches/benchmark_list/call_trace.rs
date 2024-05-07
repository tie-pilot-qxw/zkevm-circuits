//! benchmark create_proof for call_trace
use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW};
use zkevm_circuits::util::get_geth_data;

use crate::run_benchmark;

#[cfg(feature = "k_10")]
const MAX_CODESIZE_FOR_CALL_TRACE: usize = 4220;

#[cfg(not(feature = "k_10"))]
const MAX_CODESIZE_FOR_CALL_TRACE: usize = MAX_CODESIZE;

#[test]
fn bench_call_trace() {
    let degree: u32 = 14;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    let geth_data = &get_geth_data(
        "test_data/call_test/trace/block_info.json",
        "test_data/call_test/trace/tx_info.json",
        "test_data/call_test/trace/tx_debug_trace.json",
        "test_data/call_test/trace/tx_receipt.json",
        "test_data/call_test/trace/bytecode.json",
    );
    run_benchmark::<MAX_NUM_ROW, MAX_CODESIZE_FOR_CALL_TRACE>("call_trace", geth_data, degree);
}
