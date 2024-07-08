#[cfg(feature = "fuzz_test")]
mod tests {
    use crate::gen_mutate_trace_testcases;
    use seq_macro::seq;
    use test_case::test_case;
    // step1: Get baseline erc20 chunk_data from file
    // step2: Mutate geth_traces of chunk_data.blocks[0]
    // step3: Get witness form mutated chunk_data
    // step4: Get prover from witness
    // step5: Verify par and should be error
    gen_mutate_trace_testcases!(500);
}
