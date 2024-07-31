//! benchmark create_proof for call_trace
use zkevm_circuits::constant::MAX_NUM_ROW;
use zkevm_circuits::util::get_chunk_data;

use crate::run_benchmark;

#[test]
fn bench_call_trace() {
    let degree: u32 = 14;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree: u32 = 19;

    let chunk_data = &get_chunk_data(
        "test_data/call_test/trace/block_info.json",
        "test_data/call_test/trace/tx_info.json",
        "test_data/call_test/trace/tx_debug_trace.json",
        "test_data/call_test/trace/tx_receipt.json",
        "test_data/call_test/trace/bytecode.json",
    );
    run_benchmark::<MAX_NUM_ROW>("call_trace", chunk_data, degree);
}
