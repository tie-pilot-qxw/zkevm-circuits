//! benchmark create_proof for super_circuit

use zkevm_circuits::constant::{MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::util::geth_data_test;

use crate::run_benchmark;

const BENCH_ROUND: usize = 3;

#[test]
fn bench_super_circuit() {
    let degree = 9;
    #[cfg(not(feature = "no_fixed_lookup"))]
    let degree = 19;

    let machine_code = trace_parser::assemble_file("test_data/1.txt");
    let trace = trace_parser::trace_program(&machine_code, &[]);

    let geth_data = &geth_data_test(trace, &machine_code, &[], false, Default::default());

    // run benchmark
    println!("--------start super circuit benchmark--------");
    run_benchmark::<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL, BENCH_ROUND>(
        geth_data, degree,
    );
    println!("--------super circuit benchmark over--------");
}
