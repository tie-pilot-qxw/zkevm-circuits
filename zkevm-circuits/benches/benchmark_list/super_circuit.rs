//! benchmark create_proof for super_circuit

use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW};
use zkevm_circuits::util::geth_data_test;

use crate::{run_benchmark, DEFAULT_BENCH_ROUND};

#[test]
fn bench_super_circuit() {
    let degree = 9;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree = 19;

    let machine_code = trace_parser::assemble_file("test_data/1.txt");
    let trace = trace_parser::trace_program(&machine_code, &[]);

    let geth_data = &geth_data_test(trace, &machine_code, &[], false, Default::default());

    // run benchmark
    run_benchmark::<MAX_NUM_ROW, MAX_CODESIZE>(
        "super_circuit",
        geth_data,
        degree,
        DEFAULT_BENCH_ROUND,
    );
}
