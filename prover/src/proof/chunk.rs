// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use anyhow::Result;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::ProvingKey;
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use snark_verifier_sdk::snark_verifier::verifier::plonk::PlonkProtocol;
use snark_verifier_sdk::Snark;

use eth_types::base64;

use crate::constants::CHUNK_PROTOCOL_FILENAME;
use crate::proof::{dump_as_json, dump_data, dump_proof_path, from_json_file, from_json_u8, Proof};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ChunkProof {
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    #[serde(flatten)]
    pub proof: Proof,
}

impl ChunkProof {
    pub fn new(snark: Snark, pk: Option<&ProvingKey<G1Affine>>) -> Result<Self> {
        let protocol = serde_json::to_vec(&snark.protocol)?;

        let data = protocol.as_slice();
        let stream = Cursor::new(data);
        let mut deserializer = Deserializer::from_reader(stream);
        deserializer.disable_recursion_limit();
        let _protocol: PlonkProtocol<G1Affine> =
            PlonkProtocol::deserialize(&mut deserializer).unwrap();

        let proof = Proof::new(snark.proof, &snark.instances, pk);

        Ok(Self { protocol, proof })
    }

    pub fn from_json_file(dir: &str, filename: &str) -> Result<Self> {
        let file_path = dump_proof_path(dir, filename);
        from_json_file(file_path.as_str())
    }

    pub fn dump(&self, dir: &str, filename: &str) -> Result<()> {
        dump_data(dir, &CHUNK_PROTOCOL_FILENAME, &self.protocol);
        dump_as_json(dir, filename, &self)
    }

    pub fn to_snark(self) -> Snark {
        let instances = self.proof.instances();
        let protocol = from_json_u8(&self.protocol).unwrap();

        Snark {
            protocol,
            proof: self.proof.proof,
            instances,
        }
    }
}
