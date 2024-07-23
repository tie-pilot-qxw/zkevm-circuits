// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use snark_verifier_sdk::evm::encode_calldata;
use trace_parser::trace_program;

use crate::constants::{AGG_VK_FILENAME, DEPLOYMENT_CODE_FILENAME};
use crate::io::{force_to_read, try_to_read};
use crate::proof::batch::BatchProof;

use log::info;

#[derive(Debug)]
pub struct Verifier {
    deployment_code: Vec<u8>,
    /// 该vk以u8形式存在在内存里，不会反序列化，主要用于校验
    raw_vk: Vec<u8>,
}

impl Verifier {
    /// deployment_code 应该是通用的，也即提前生成好一份放在代码里应该就可以
    pub fn new(raw_vk: Vec<u8>, deployment_code: Vec<u8>) -> Self {
        Self {
            raw_vk,
            deployment_code,
        }
    }

    pub fn from_dirs(assets_dir: &str) -> Self {
        let raw_vk = try_to_read(assets_dir, &AGG_VK_FILENAME).unwrap();
        let deployment_code = force_to_read(assets_dir, &DEPLOYMENT_CODE_FILENAME);

        Self::new(raw_vk, deployment_code)
    }

    /// 依赖go-ethereum编译后的可执行文件，evm二进制文件，替代revm
    pub fn verify_agg_evm_proof(&self, batch_proof: BatchProof) -> bool {
        let call_data = encode_calldata(&batch_proof.instance(), &batch_proof.proof());
        let trace = trace_program(self.deployment_code.as_slice(), &call_data);
        info!("evm gas used: {}", trace.gas);
        !trace.failed
    }
    pub fn get_vk(&self) -> Option<Vec<u8>> {
        Some(self.raw_vk.clone())
    }
}

#[cfg(test)]
mod test {
    use crate::batch::verifier::Verifier;
    use crate::constants::{AGG_DEGREE_FOR_TEST, DEFAULT_PROOF_PARAMS_DIR};
    use crate::proof::batch::BatchProof;
    use crate::test::proof_test::BATCH_TEST_INIT;

    #[test]
    fn test_verifier() {
        let _ = &*BATCH_TEST_INIT;
        let verifier = Verifier::from_dirs(DEFAULT_PROOF_PARAMS_DIR);
        let batch_proof = BatchProof::from_json_file(
            DEFAULT_PROOF_PARAMS_DIR,
            format!("batch_k{}", AGG_DEGREE_FOR_TEST).as_str(),
        )
        .unwrap();
        assert!(verifier.verify_agg_evm_proof(batch_proof))
    }
}
