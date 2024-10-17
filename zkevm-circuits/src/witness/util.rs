// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;
use crate::constant::BIT_SHIFT_MAX_IDX;
use crate::util::create_contract_addr_with_prefix;
use crate::witness::{arithmetic, assign_or_panic, bitwise, core, exp};
use eth_types::evm_types::OpcodeId;
use eth_types::geth_types::GethData;
use eth_types::{Field, GethExecStep, StateDB, U256};
use std::collections::HashSet;

pub fn get_and_insert_shl_shr_rows<F: Field>(
    shift: U256,
    value: U256,
    op: OpcodeId,
    core_row_1: &mut core::Row,
    core_row_2: &mut core::Row,
) -> (Vec<arithmetic::Row>, Vec<exp::Row>) {
    // 255 - a
    // the main purpose is to determine whether shift is greater than or equal to 256
    // that is, whether 2<<shift will overflow
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![BIT_SHIFT_MAX_IDX.into(), shift]);

    // mul_div_num = 2<<stack_shift
    let (mul_div_num, exp_rows, exp_arith_mul_rows) = exp::Row::from_operands(U256::from(2), shift);

    // if Opcode is SHL, then result is stack_value * mul_div_num
    // if Opcode is SHR, then result is stack_value / mul_div_num
    let (arithmetic_mul_div_rows, _) = match op {
        OpcodeId::SHL => operation::mul::gen_witness(vec![value, mul_div_num]),
        OpcodeId::SHR => operation::div_mod::gen_witness(vec![value, mul_div_num]),
        _ => panic!("not shl or shr"),
    };

    // insert arithmetic-sub in lookup
    core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
    // insert arithmetic-mul_div in lookup
    core_row_2.insert_arithmetic_lookup(1, &arithmetic_mul_div_rows);

    // insert exp lookup
    core_row_1.insert_exp_lookup(U256::from(2), shift, mul_div_num);

    let mut arithmetic_rows = vec![];
    arithmetic_rows.extend(arithmetic_sub_rows);
    arithmetic_rows.extend(arithmetic_mul_div_rows);
    arithmetic_rows.extend(exp_arith_mul_rows);

    (arithmetic_rows, exp_rows)
}

pub fn get_and_insert_signextend_rows<F: Field>(
    signextend_operands: [U256; 2],
    arithmetic_operands: [U256; 2],
    core_row_0: &mut core::Row,
    _core_row_1: &mut core::Row,
    core_row_2: &mut core::Row,
) -> (Vec<bitwise::Row>, Vec<arithmetic::Row>) {
    // get arithmetic rows
    let (arithmetic_sub_rows, _) =
        operation::sub::gen_witness(vec![arithmetic_operands[0], arithmetic_operands[1]]);
    const START_COL_IDX: usize = 25;

    // calc signextend by bit
    let (signextend_result_vec, bitwise_rows_vec) =
        signextend_by_bit::<F>(signextend_operands[0], signextend_operands[1]);

    // insert bitwise lookup
    for (i, bitwise_lookup) in bitwise_rows_vec.iter().enumerate() {
        core_row_2.insert_bitwise_lookups(i, bitwise_lookup.last().unwrap());
    }
    // insert arithmetic lookup to core_row_2
    core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);

    // a_hi set core_row_0.vers_25;
    // a_lo set core_row_0.vers_26;
    // d_hi set core_row_0.vers_27
    // d_lo set core_row_0.vers_28
    // sign_bit_is_zero_inv set core_row_0.vers_29;
    for (i, value) in (0..5).zip(signextend_result_vec) {
        assign_or_panic!(core_row_0[i + START_COL_IDX], value);
    }
    // Construct Witness object
    let bitwise_rows = bitwise_rows_vec
        .into_iter()
        .flat_map(|inner_vec| inner_vec.into_iter())
        .collect();

    (bitwise_rows, arithmetic_sub_rows)
}

/// signextend operations
/// Specify the `n`th `bit` as the symbol to perform sign bit extension on the `value`. The value range of n is 0~255
/// a is 2^n
/// value is the original value to be sign-bit extended
/// for specific calculation steps, please refer to the code comments.
fn signextend_by_bit<F: Field>(a: U256, value: U256) -> (Vec<U256>, Vec<Vec<bitwise::Row>>) {
    // calculate whether the `n`th `bit` of `value` is 0 or 1 based on `a` and `value`
    let a_lo: U256 = a.low_u128().into();
    let a_hi = a >> 128;
    let operand_1_hi_128 = value >> 128;
    let operand_1_lo_128: U256 = value.low_u128().into();
    let bitwise_rows1 = bitwise::Row::from_operation::<F>(
        bitwise::Tag::And,
        operand_1_hi_128.as_u128(),
        a_hi.as_u128(),
    );

    let bitwise_rows2 = bitwise::Row::from_operation::<F>(
        bitwise::Tag::And,
        operand_1_lo_128.as_u128(),
        a_lo.as_u128(),
    );

    // if bitwise sum is 0, it means that the position of shift is 0
    // if bitwise sum is not 0, it means that the position of shift is 1
    let sign_bit_is_zero =
        bitwise_rows1.last().unwrap().sum_2 + bitwise_rows2.last().unwrap().sum_2;

    // bitwise sum is byte+prev_byte, max_vaule is 2^7 * 32(2^12)
    let sign_bit_is_zero_inv = U256::from_little_endian(
        F::from_u128(sign_bit_is_zero.low_u128())
            .invert()
            .unwrap_or(F::ZERO)
            .to_repr()
            .as_ref(),
    );

    // get b
    // 1. a_lo = 0, then b_lo = 2^128 -1 ;
    // 2. a_lo <> 0, then b_lo = 2*a_lo -1 ;
    let max_u128 = U256::from(2).pow(U256::from(128)) - 1;
    let b_lo = if a_lo.is_zero() {
        max_u128.clone()
    } else {
        a_lo * 2 - 1
    };
    // 1. a_hi <> 0 , then b_hi = 2*a_hi -1
    // 2. a.hi = 0, a_lo = 0, then b_hi = 2^128 -1;
    // 3. a_hi = 0, a_lo <> 0, then b_hi = 0;
    let b_hi = if a_hi.is_zero() {
        if a_lo.is_zero() {
            max_u128.clone()
        } else {
            0.into()
        }
    } else {
        a_hi * 2 - 1
    };

    // get c
    // 1. if a_lo == 0 ,c_lo =0;
    // 2. if a_lo <> 0, c_lo = 2^128 - 2*a_lo
    let c_lo = if a_lo.is_zero() {
        0.into()
    } else {
        max_u128 + 1 - a_lo * 2
    };
    // get c_hi
    let c_hi = if a_hi.is_zero() {
        if a_lo.is_zero() {
            0.into()
        } else {
            max_u128
        }
    } else {
        max_u128 + 1 - a_hi * 2
    };

    // 1.  if sign_bit_is_zero is not 0 , then d = c, op_result = operand_1 || d
    // 2. if sign_bit_is_zero is 0, then d = b , op_result = operand_1 & d
    // get bitwise operator tag
    let (d_hi, d_lo, op_tag) = if sign_bit_is_zero.is_zero() {
        (b_hi, b_lo, bitwise::Tag::And)
    } else {
        (c_hi, c_lo, bitwise::Tag::Or)
    };

    // get bitwise rows
    // bitwise_rows3.acc[2] is result hi
    // bitwise_rows4.acc[2] is result lo
    let bitwise_rows3 =
        bitwise::Row::from_operation::<F>(op_tag, operand_1_hi_128.as_u128(), d_hi.as_u128());
    let bitwise_rows4 =
        bitwise::Row::from_operation::<F>(op_tag, operand_1_lo_128.as_u128(), d_lo.low_u128());
    (
        // calc result
        vec![a_hi, a_lo, d_hi, d_lo, sign_bit_is_zero_inv],
        // bitwise rows
        vec![bitwise_rows1, bitwise_rows2, bitwise_rows3, bitwise_rows4],
    )
}

pub fn handle_sload(
    to: U256,
    step: &GethExecStep,
    state_db: &mut StateDB,
    first_access: &mut HashSet<(U256, U256)>,
) {
    for (key, value) in &step.storage.0 {
        if !first_access.contains(&(to, *key)) {
            state_db.insert_original_storage(to, *key, value.clone());
            first_access.insert((to, *key));
        }
    }
}

// 传入的tx_idx下标从1开始计数
pub fn handle_sstore(to: U256, step: &GethExecStep, state_db: &mut StateDB, tx_idx: usize) {
    for (key, value) in &step.storage.0 {
        if !state_db.check_pending_storage(to, *key, tx_idx) {
            // 倒序遍历，如果同一笔交易里有两个sstore操作，并且他们的key元组相同，那么只保留第一次插入的值
            state_db.insert_pending_storage(to, *key, value.clone(), tx_idx);
        }
    }
}

pub fn extract_address_from_tx(geth_data: &GethData, index: usize) -> U256 {
    let tx = geth_data
        .eth_block
        .transactions
        .get(index)
        .expect("tx_idx out of bounds");
    let to = tx.to.map_or_else(
        || create_contract_addr_with_prefix(&tx),
        |to| to.as_bytes().into(),
    );
    to
}
