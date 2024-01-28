//! benchmark create_proof for call_trace
use zkevm_circuits::constant::{MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::util::get_geth_data;

use crate::run_benchmark;

const MAX_CODESIZE_FOR_CALL_TRACE: usize = 4220;
const BENCH_ROUND: usize = 3;

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

    println!("--------start call trace benchmark--------");
    run_benchmark::<
        MAX_NUM_ROW,
        MAX_CODESIZE_FOR_CALL_TRACE,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
        BENCH_ROUND,
    >(geth_data, degree);
    println!("--------call trace benchmark over--------");
}
