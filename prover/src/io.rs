// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Result;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use halo2_proofs::halo2curves::bn256::Bn256;

use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

pub fn try_to_read(dir: &str, filename: &str) -> Option<Vec<u8>> {
    let mut path = PathBuf::from(dir);
    path.push(filename);

    if path.exists() {
        Some(read_all(&path.to_string_lossy()))
    } else {
        None
    }
}

pub fn read_all(filename: &str) -> Vec<u8> {
    let mut buf = vec![];
    let mut fd = File::open(filename).unwrap();
    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn force_to_read(dir: &str, filename: &str) -> Vec<u8> {
    try_to_read(dir, filename).unwrap_or_else(|| panic!("File {filename} must exist in {dir}"))
}

pub fn read_params(dir: &str, filename: &str) -> Result<ParamsKZG<Bn256>> {
    let mut path = PathBuf::from(dir);
    path.push(filename);
    let f = File::open(path).unwrap();
    let mut reader = BufReader::new(f);
    ParamsKZG::<Bn256>::read(&mut reader)
}
