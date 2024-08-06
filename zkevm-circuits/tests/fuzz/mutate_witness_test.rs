// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "fuzz_test")]
mod tests {
    use crate::gen_mutate_witness_testcases;
    use seq_macro::seq;
    use test_case::test_case;
    // Generate fuzz testcases for witness mutation
    // step1: Get baseline witness (erc20)
    // step2: Generate random seed: sub_circuit_choice, row_choice, column_choice, value_delta
    // step3: Mutate witness:
    //   - 3.1 Choose sub_circuit by sub_circuit_choice, eg: witness.core
    //   - 3.2 Choose row by row_choice % sub_circuit.len(), eg: witness.core[567]
    //   - 3.3 Mutate certain cell by column_choice: eg: (witness.core[567].pc += value_delta) % column_num
    // step4: Get prover from witness
    // step5: Verify par and should be error
    gen_mutate_witness_testcases!(500);
}
