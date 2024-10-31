// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::POSEIDON_HASH_BYTES_IN_FIELD;
use crate::table::PoseidonTable;
use eth_types::{Field, U256};
use serde::Serialize;
/// poseidon row
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// input_0
    pub input_0: U256,
    /// input_1
    pub input_1: U256,
    /// control
    pub control: u64,
    /// domain
    pub domain: Option<U256>,
    /// checks
    pub check: Option<U256>,
}

/// src指向的是input，可以参考相关示例
/// 该函数主要用于code_hash，domain及checks都为None
pub fn get_poseidon_row_from_stream_input<'d>(
    src: impl IntoIterator<Item = &'d [U256; 2]>,
    check: Option<U256>,
    ctrl_start: u64,
    step: usize,
) -> Vec<Row> {
    let mut new_inps: Vec<[U256; 2]> = src.into_iter().copied().collect();
    assert_ne!(0, new_inps.len());
    let mut ctrl_series: Vec<u64> = std::iter::successors(Some(ctrl_start), |n| {
        if *n > (step as u64) {
            Some(n - step as u64)
        } else {
            None
        }
    })
    .take(new_inps.len())
    .collect();
    assert_eq!(new_inps.len(), ctrl_series.len());

    let mut checks = vec![None; new_inps.len() - 1];
    checks.push(check);
    let domain = vec![None; new_inps.len()];

    new_inps
        .into_iter()
        .zip(ctrl_series)
        .zip(checks)
        .zip(domain)
        .map(|((([input_0, input_1], control), check), domain)| Row {
            input_0,
            input_1,
            control,
            check,
            domain,
        })
        .collect()
}

/// Get unrolled hash inputs as inputs to hash circuit
/// 将code byte 按照31字节转化为了U256，然后转化为Fr，最后再 2 2 分组
pub fn get_hash_input_from_u8s<F: Field, const BYTES_IN_FIELD: usize, const INPUT_LEN: usize>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[U256; INPUT_LEN]> {
    let fl_cnt = code.len() / BYTES_IN_FIELD;
    let fl_cnt = if code.len() % BYTES_IN_FIELD != 0 {
        fl_cnt + 1
    } else {
        fl_cnt
    };

    let (msgs, _) = code
        .chain(std::iter::repeat(0))
        .take(fl_cnt * BYTES_IN_FIELD)
        .fold((Vec::new(), Vec::new()), |(mut msgs, mut cache), bt| {
            cache.push(bt);
            if cache.len() == BYTES_IN_FIELD {
                let value = U256::from_big_endian(&cache);
                msgs.push(value);
                cache.clear();
            }
            (msgs, cache)
        });

    let input_cnt = msgs.len() / INPUT_LEN;
    let input_cnt = if msgs.len() % INPUT_LEN != 0 {
        input_cnt + 1
    } else {
        input_cnt
    };
    if input_cnt == 0 {
        return Vec::new();
    }

    // 把msg从Vec<F>分割为Vec<[F;2]>
    let (mut inputs, last) = msgs
        .into_iter()
        .chain(std::iter::repeat(U256::zero()))
        .take(input_cnt * INPUT_LEN)
        .fold(
            (Vec::new(), [None; INPUT_LEN]),
            |(mut msgs, mut v_arr), f| {
                if let Some(v) = v_arr.iter_mut().find(|v| v.is_none()) {
                    v.replace(f);
                    (msgs, v_arr)
                } else {
                    msgs.push(v_arr.map(|v| v.unwrap()));
                    let mut v_arr = [None; INPUT_LEN];
                    v_arr[0].replace(f);
                    (msgs, v_arr)
                }
            },
        );

    inputs.push(last.map(|v| v.unwrap()));
    inputs
}

/// Apply default constants in mod
pub fn get_hash_input_from_u8s_default<F: Field>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[U256; PoseidonTable::INPUT_WIDTH]> {
    get_hash_input_from_u8s::<F, POSEIDON_HASH_BYTES_IN_FIELD, { PoseidonTable::INPUT_WIDTH }>(code)
}
