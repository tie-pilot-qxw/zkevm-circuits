// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::evm::encode_calldata;

use crate::proof::{dump_as_json, dump_proof_path, from_json_file, Proof};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchProof {
    #[serde(flatten)]
    raw: Proof,
}

impl From<Proof> for BatchProof {
    fn from(proof: Proof) -> Self {
        Self { raw: proof }
    }
}

impl BatchProof {
    pub fn from_json_file(dir: &str, file_name: &str) -> Result<Self> {
        let file_path = dump_proof_path(dir, file_name);
        from_json_file(file_path.as_str())
    }

    pub fn calldata(self) -> Vec<u8> {
        // calldata = instances + proof
        let mut calldata = self.raw.instances;
        calldata.extend(self.raw.proof);

        calldata
    }

    pub fn instance(&self) -> Vec<Vec<Fr>> {
        self.raw.instances()
    }

    pub fn proof(&self) -> Vec<u8> {
        self.raw.proof.clone()
    }
    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        dump_as_json(dir, &dump_filename(name), &self)
    }

    pub fn assert_calldata(self) {
        let real_calldata = self.clone().calldata();

        let expected_calldata = encode_calldata(&self.raw.instances(), &self.raw.proof);

        assert_eq!(real_calldata, expected_calldata);
    }
}

fn dump_filename(name: &str) -> String {
    format!("batch_{name}")
}
