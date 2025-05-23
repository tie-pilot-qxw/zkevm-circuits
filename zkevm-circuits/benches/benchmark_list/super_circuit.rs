// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! benchmark create_proof for super_circuit

use zkevm_circuits::constant::MAX_NUM_ROW;
use zkevm_circuits::util::{chunk_data_test, log2_ceil};

use crate::run_benchmark;

#[test]
#[cfg(feature = "evm")]
fn bench_super_circuit() {
    let degree = 22;

    let machine_code = trace_parser::assemble_file("test_data/1.txt");
    let trace = trace_parser::trace_program(&machine_code, &[]);

    let chunk_data = &chunk_data_test(trace, &machine_code, &[], false, Default::default());

    // run benchmark
    run_benchmark::<MAX_NUM_ROW>("super_circuit", chunk_data, degree);
}
