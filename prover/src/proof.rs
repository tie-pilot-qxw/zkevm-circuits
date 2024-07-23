// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::{Circuit, ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use eth_types::base64;

use crate::util::{deserialize_vk, serialize_vk};

pub mod batch;
pub mod chunk;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Proof {
    #[serde(with = "base64")]
    proof: Vec<u8>,
    #[serde(with = "base64")]
    instances: Vec<u8>,
    #[serde(with = "base64")]
    vk: Vec<u8>,
}

impl Proof {
    pub fn new(proof: Vec<u8>, instances: &[Vec<Fr>], pk: Option<&ProvingKey<G1Affine>>) -> Self {
        let vk = pk.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));
        let instances = serialize_instances(instances);

        Self {
            proof,
            instances,
            vk,
        }
    }

    pub fn dump(&self, dir: &str, filename: &str) -> Result<()> {
        dump_as_json(dir, filename, &self)
    }

    pub fn from_json_file(dir: &str, filename: &str) -> Result<Self> {
        let file_path = dump_proof_path(dir, filename);
        from_json_file(file_path.as_str())
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        let instance: Vec<Fr> = self
            .instances
            .chunks(32)
            .map(|bytes| deserialize_fr(bytes.iter().rev().cloned().collect()))
            .collect();

        vec![instance]
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

pub fn dump_proof_path(dir: &str, filename: &str) -> String {
    format!("{dir}/full_proof_{filename}.json")
}

pub fn write_file(folder: &mut PathBuf, filename: &str, buf: &[u8]) {
    folder.push(filename);
    let mut fd = File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(buf).unwrap();
}

pub fn from_json_file<'de, P: serde::Deserialize<'de>>(file_path: &str) -> Result<P> {
    if !Path::new(&file_path).exists() {
        bail!("File {file_path} doesn't exist");
    }

    // 不限制递归次数的json解析，因为序列化后的结构体会很复杂，使用此方法能够忽视反序列化递归次数
    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(Deserialize::deserialize(deserializer)?)
}

pub fn from_json_u8<'de, P: serde::Deserialize<'de>>(data: &[u8]) -> Result<P> {
    let stream = Cursor::new(data);
    let mut deserializer = serde_json::Deserializer::from_reader(stream);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(Deserialize::deserialize(deserializer)?)
}

fn serialize_instances(instances: &[Vec<Fr>]) -> Vec<u8> {
    assert_eq!(instances.len(), 1);
    serialize_instance(&instances[0])
}

fn serialize_instance(instance: &[Fr]) -> Vec<u8> {
    let bytes: Vec<_> = instance
        .iter()
        .flat_map(|value| serialize_fr(value).into_iter().rev())
        .collect();
    assert_eq!(bytes.len() % 32, 0);

    bytes
}

pub fn serialize_fr(f: &Fr) -> Vec<u8> {
    f.to_bytes().to_vec()
}

pub fn deserialize_fr(buf: Vec<u8>) -> Fr {
    Fr::from_repr(buf.try_into().unwrap()).unwrap()
}
