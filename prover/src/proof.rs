// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{Circuit, ProvingKey, VerifyingKey};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize};

use crate::util::{deserialize_vk, serialize_vk};
use eth_types::base64;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Proof {
    #[serde(with = "base64")]
    proof: Vec<u8>,
    instances: Vec<Vec<Fr>>,
    #[serde(with = "base64")]
    vk: Vec<u8>,
}

impl Proof {
    pub fn new(proof: Vec<u8>, instances: Vec<Vec<Fr>>, pk: Option<&ProvingKey<G1Affine>>) -> Self {
        let vk = pk.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));

        Self {
            proof,
            instances,
            vk,
        }
    }

    pub fn dump(&self, dir: &str, filename: &str) -> Result<()> {
        dump_vk(dir, filename, &self.vk);

        dump_as_json(dir, filename, &self)
    }

    pub fn from_json_file(dir: &str, filename: &str) -> Result<Self> {
        let path = dump_proof_path(dir, filename);
        let file = File::open(path).expect("file should exist");
        let reader = BufReader::new(file);
        let proof: Proof = serde_json::from_reader(reader).unwrap();
        Ok(proof)
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        self.instances.clone()
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn raw_vk(&self) -> &[u8] {
        &self.vk
    }

    pub fn vk<C: Circuit<Fr>>(&self, params: C::Params) -> VerifyingKey<G1Affine> {
        deserialize_vk::<C>(&self.vk, params)
    }
}

pub fn dump_as_json<P: serde::Serialize>(dir: &str, filename: &str, proof: &P) -> Result<()> {
    // Write full proof as json.
    let mut fd = File::create(dump_proof_path(dir, filename))?;
    serde_json::to_writer(&mut fd, proof)?;

    Ok(())
}

pub fn dump_data(dir: &str, filename: &str, data: &[u8]) {
    write_file(&mut PathBuf::from(dir), filename, data);
}

pub fn dump_vk(dir: &str, filename: &str, raw_vk: &[u8]) {
    dump_data(dir, &format!("{filename}.vk"), raw_vk);
}

fn dump_proof_path(dir: &str, filename: &str) -> String {
    format!("{dir}/full_proof_{filename}.json")
}

pub fn write_file(folder: &mut PathBuf, filename: &str, buf: &[u8]) {
    folder.push(filename);
    let mut fd = File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(buf).unwrap();
}

pub fn from_json_file<'de, P: serde::Deserialize<'de>>(dir: &str, filename: &str) -> Result<P> {
    let file_path = dump_proof_path(dir, filename);
    if !Path::new(&file_path).exists() {
        bail!("File {file_path} doesn't exist");
    }

    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(Deserialize::deserialize(deserializer)?)
}
