// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::{self};
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;
const PC_DELTA: u64 = 1;

const HASH_TAG_COL_OFFSET: usize = 16;
const RIGHT_TAG_COL_OFFSET: usize = 17;

/// BLOCKHASH overview:
/// Get the hash of one of the 256 most recent complete blocks by block number
/// and put it on the top of the stack.
/// ARITH0 means u64 overflow arithmetic lookup
/// ARITH1 means u64 div arithmetic lookup
/// ARITH2 means sub arithmetic lookup
/// PUBLIC0 means public lookup for block hash
/// PUBLIC1 means public lookup for block number
/// TAG0 means hash tag
/// TAG1 means right tag
/// BLOCKHASH Execution State layout is as follows
/// where STATE0 means state table lookup(POP),
/// STATE1 means state table lookup(PUSH),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+--------+-------+-------+----------+
/// |cnt| 8 col  | 8 col | 8 col |  8 col   |
/// +---+--------+-------+-------+----------+
/// | 2 | |ARITH0|ARITH1|  |PUBLIC0| PUBLIC1|
/// | 1 | STATE0|STATE1|TAG0|TAG1|ARITH2|   |
/// | 0 | DYNA_SELECTOR   | AUX |           |
/// +---+--------+-------+-------+----------+
pub struct BlockHashGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BlockHashGadget<F>
{
    fn name(&self) -> &'static str {
        "BLOCKHASH"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BLOCKHASH
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // get hash tag
        let hash_tag = meta.query_advice(config.vers[HASH_TAG_COL_OFFSET], Rotation::prev());

        // get right tag
        let right_tag = meta.query_advice(config.vers[RIGHT_TAG_COL_OFFSET], Rotation::prev());

        // constraints all tag is 0 or 1
        constraints.extend([
            (
                "hash tag is 0 or 1".into(),
                hash_tag.clone() * (hash_tag.clone() - 1.expr()),
            ),
            (
                "right tag is 0 or 1".into(),
                right_tag.clone() * (right_tag.clone() - 1.expr()),
            ),
        ]);

        // get stack operands
        let mut stack_operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                0.expr(),
                i == 1,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }
        // rename
        let block_number_pop_hi = stack_operands[0][0].clone();
        let block_number_pop_lo = stack_operands[0][1].clone();
        let hash_push_hi = stack_operands[1][0].clone();
        let hash_push_lo = stack_operands[1][1].clone();

        // get public entry: BLOCKHASH
        let public_entry_0 = config.get_public_lookup(meta, 0);
        let (
            pub_tag_0,
            max_block_idx,
            [first_hash_hi, first_hash_lo, second_hash_hi, second_hash_lo],
        ) = extract_lookup_expression!(public, public_entry_0);
        // constraints for public tag
        constraints.push((
            "public tag is BlockHash".into(),
            pub_tag_0.clone() - (public::Tag::BlockHash as u8).expr(),
        ));

        // get public entry: BLOCKNUMBER
        let public_entry_1 = config.get_public_lookup(meta, 1);
        let (pub_tag_1, _, [_, block_number_first, _, _]) =
            extract_lookup_expression!(public, public_entry_1);
        // constraints for public tag.
        constraints.push((
            "public tag is BLOCKNUMBER".into(),
            pub_tag_1.clone() - (public::Tag::BlockNumber as u8).expr(),
        ));

        // constraints for block number pop
        // calculate block number form public entry
        let block_idx_cur = meta.query_advice(config.block_idx, Rotation::cur());
        let block_number_cur = block_number_first.clone() + block_idx_cur.clone() - 1.expr();
        let block_number_pub =
            block_number_first.clone() + max_block_idx.clone() + right_tag.clone() - 257.expr();
        // when hash_tag is 1, constraints block_number_pop = block_number_pub
        constraints.push((
            "block_number_pop = block_number_pub".into(),
            hash_tag.clone() * (block_number_pop_lo.clone() - block_number_pub.clone()),
        ));
        // when hash_tag is 0, constraints max_block_idx = 0
        constraints.push((
            "when hash_tag is 0, max_block_idx = 0".into(),
            (1.expr() - hash_tag.clone()) * max_block_idx.clone(),
        ));

        // constraints for block hash
        // When hash tag is 1, constrants hash_push = hash_pub
        // otherwise, hash_push = hash_pub = 0
        let hash_pub_hi = (1.expr() - right_tag.clone()) * first_hash_hi.clone()
            + right_tag.clone() * second_hash_hi.clone();
        let hash_pub_lo = (1.expr() - right_tag.clone()) * first_hash_lo.clone()
            + right_tag.clone() * second_hash_lo.clone();
        constraints.extend([
            (
                "block_hash_hi = hash_pub_hi".into(),
                hash_push_hi.clone() - hash_pub_hi.clone(),
            ),
            (
                "block_hash_lo = hash_pub_lo".into(),
                hash_push_lo.clone() - hash_pub_lo.clone(),
            ),
            (
                "when hash_tag is 0, block_hash_hi = 0".into(),
                (1.expr() - hash_tag.clone()) * hash_push_hi.clone(),
            ),
            (
                "when hash_tag is 0, block_hash_lo = 0".into(),
                (1.expr() - hash_tag.clone()) * hash_push_lo.clone(),
            ),
        ]);

        // get sub arithmetic entry
        // if diff < 256, within_range_tag = 1, otherwise 0.
        let (arith_full_tag, [diff_hi, diff_lo, range_hi, range_lo, _, _, within_range_tag, _]) = extract_lookup_expression!(
            arithmetic,
            config.get_arithmetic_lookup_with_rotation(meta, 2, Rotation::prev())
        );
        // constraints for sub operands
        constraints.extend([
            (
                "div arithmetic tag".into(),
                arith_full_tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
            ),
            (
                "diff = block_number_cur - block_number_pop - 1".into(),
                diff_hi.clone() * pow_of_two::<F>(128) + diff_lo.clone()
                    - (block_number_cur.clone()
                        - (block_number_pop_hi.clone() * pow_of_two::<F>(128)
                            + block_number_pop_lo.clone())
                        - 1.expr()),
            ),
            ("range_hi = 0".into(), range_hi.clone()),
            ("range_lo = 256".into(), range_lo.clone() - 256.expr()),
        ]);

        // get u64 overflow arithmetic entry
        let (arith_tag_0, [num_hi, num_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));
        // constraints for block number u64 overflow
        constraints.extend([
            (
                "u64 overflow arithmetic tag".into(),
                arith_tag_0.clone() - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
            (
                "u64 overflow arithmetic num_hi".into(),
                num_hi.clone() - block_number_pop_hi.clone(),
            ),
            (
                "u64 overflow arithmetic num_lo".into(),
                num_lo.clone() - block_number_pop_lo.clone(),
            ),
            (
                "if not overflow, block_number_pop_hi = 0".into(),
                (1.expr() - overflow.clone() * overflow_inv.clone()) * block_number_pop_hi.clone(),
            ),
        ]);

        // constraints for within_range_tag, u64overflow and hash_tag
        constraints.extend([
            (
                "if hash_tag = 1, not overflow".into(),
                hash_tag.clone() * overflow.clone() * overflow_inv.clone(),
            ),
            (
                "if hash_tag = 1, within_range_tag = 1".into(),
                hash_tag.clone() * (1.expr() - within_range_tag.clone()),
            ),
            (
                "if hash_tag = 0, within_range_tag = 0 || overflow".into(),
                // overflow_inv is enough here
                (1.expr() - hash_tag.clone()) * within_range_tag.clone() * overflow_inv.clone(),
            ),
        ]);

        // get u64 div arithmetic entry
        let (arith_tag_1, [numerator, denominator, _, remainder]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 1));
        // constraints for block number u64 div
        constraints.extend([
            (
                "u64 div arithmetic tag".into(),
                arith_tag_1.clone() - (arithmetic::Tag::U64Div as u8).expr(),
            ),
            (
                "when hash tag = 1, numerator = block_number_pop_lo".into(),
                hash_tag.clone() * (numerator.clone() - block_number_pop_lo.clone()),
            ),
            (
                "when hash_tag = 0, numerator = 0".into(),
                (1.expr() - hash_tag.clone()) * numerator.clone(),
            ),
            (
                "u64 div arithmetic denominator = 2".into(),
                denominator.clone() - 2.expr(),
            ),
        ]);

        // constraints for right_tag
        constraints.extend([
            (
                "when hash_tag = 1, right_tag = 1 - remainder".into(),
                hash_tag.clone() * (1.expr() - remainder.clone() - right_tag.clone()),
            ),
            (
                "when hash_tag = 0, right_tag = 0".into(), // no need to constraints remainder when hash_tag = 0
                (1.expr() - hash_tag.clone()) * right_tag.clone(),
            ),
        ]);

        // constraints for opcode
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.push((
            "opcode is BLOCKHASH".into(),
            opcode.clone() - OpcodeId::BLOCKHASH.as_u8().expr(),
        ));

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-OpcodeId::BLOCKHASH.constant_gas_cost().expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_pop_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_push_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let public_lookup_0 = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        let public_lookup_1 = query_expression(meta, |meta| config.get_public_lookup(meta, 1));
        let arith_tiny_lookup_0 =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        let arith_tiny_lookup_1 =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 1));
        let arith_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_lookup_with_rotation(meta, 2, Rotation::prev())
        });

        vec![
            ("stack pop lookup".into(), stack_pop_lookup),
            ("stack push lookup".into(), stack_push_lookup),
            ("public lookup(block hash)".into(), public_lookup_0),
            ("public lookup(block number)".into(), public_lookup_1),
            (
                "arith tiny lookup(u64 overflow)".into(),
                arith_tiny_lookup_0,
            ),
            ("arith tiny lookup(u64 div)".into(), arith_tiny_lookup_1),
            ("arith lookup(sub)".into(), arith_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::BLOCKHASH);
        // calculate block number cur
        let block_number_cur =
            (current_state.block_number_first_block as usize + current_state.block_idx - 1).into();

        // get stack pop value: block number
        let (stack_pop_row, block_number) = current_state.get_pop_stack_row_value(&trace);

        // calculate within_range_tag, when block_number is within range, within_range_tag is 1
        let within_range_tag = if block_number < block_number_cur
            && block_number >= block_number_cur.saturating_sub(U256::from(256))
        {
            U256::one()
        } else {
            U256::zero()
        };

        // calculate hash_tag, when block_number is out of range || overflow, hash_tag is 0
        let hash_tag = if block_number >= U256::from(u64::MAX) || within_range_tag.is_zero() {
            U256::zero()
        } else {
            U256::one()
        };

        // calculate right_tag,
        // when hash in blockhash public entry |value0|value1|, right_tag is 0;
        // otherwise, right_tag is 1.
        // And we could calculate right_tag by block_number is odd or even.
        let right_tag = if hash_tag.is_zero() {
            U256::zero() // when hash_tag is 0, we set right_tag = 0
        } else {
            U256::one() - block_number.div_mod(U256::from(2)).1
        };

        // get stack push value: block hash
        let block_hash = if hash_tag.is_zero() {
            U256::zero()
        } else {
            current_state
                .block_hash_list
                .get(&block_number.as_u64())
                .unwrap() // if cannot find the block hash, panic
                .clone()
        };
        let stack_push_row = current_state.get_push_stack_row(&trace, block_hash);

        // row 2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        // get public row
        let public_row_0 =
            current_state.get_public_block_hash_row(block_number, !hash_tag.is_zero());
        let public_row_1 = current_state.get_public_tx_row(public::Tag::BlockNumber, 1);

        // block number u64 overflow
        let (u64_overflow_row, _) = operation::u64overflow::gen_witness::<F>(vec![block_number]);
        // block number u64 div for constrain right_tag, when hash_tag is 0, set block_number = 0
        let (u64_div_row, _) = operation::u64div::gen_witness(vec![
            if hash_tag.is_zero() {
                0.into()
            } else {
                block_number
            },
            2.into(),
        ]);

        core_row_2.insert_public_lookup(0, &public_row_0);
        core_row_2.insert_public_lookup(1, &public_row_1);
        core_row_2.insert_arithmetic_tiny_lookup(0, &u64_overflow_row);
        core_row_2.insert_arithmetic_tiny_lookup(1, &u64_div_row);

        // row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_row, &stack_push_row]);

        // Simulate the calculation of diff on elliptic curve
        let b_hi = (block_number >> 128).low_u128();
        let b_lo = block_number.low_u128();
        // diff = block_number_cur - block_number - 1
        let diff_f = F::from_u128(block_number_cur.as_u128())
            - (F::from_u128(b_hi) * pow_of_two::<F>(128) + F::from_u128(b_lo))
            - F::ONE; // U8: 0-255, so -1
        let diff = U256::from_little_endian(diff_f.to_repr().as_ref());

        let (div_row, _) = operation::sub::gen_witness(vec![diff, 256.into()]);
        core_row_1.insert_arithmetic_lookup(2, &div_row);

        assign_or_panic!(core_row_1[HASH_TAG_COL_OFFSET], hash_tag.into());
        assign_or_panic!(core_row_1[RIGHT_TAG_COL_OFFSET], right_tag.into());

        // row 0
        let core_row_0 = ExecutionState::BLOCKHASH.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(u64_overflow_row);
        arithmetic_rows.extend(u64_div_row);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_row, stack_push_row],
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BlockHashGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::collections::HashMap;
    use std::u128;
    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, block_idx: usize, block_hash_list: HashMap<u64, U256>, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            block_number_first_block: 1257,
            block_hash_list: block_hash_list,
            block_idx: block_idx,
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + OpcodeId::BLOCKHASH.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, OpcodeId::BLOCKHASH, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 1.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_blockhash_usual_odd() {
        let block_number = U256::from(1003); // right_tag = 0
        let stack = Stack::from_slice(&[block_number]);
        let block_idx = 1;
        let mut block_hash_list = HashMap::new();
        for i in 1001..=1260 {
            block_hash_list.insert(i, U256::from(i));
        }

        let hash = U256::from_str_radix(
            "0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470",
            16,
        )
        .unwrap();
        block_hash_list.insert(1003, hash);

        run(stack.clone(), block_idx, block_hash_list.clone(), hash);
    }

    #[test]
    fn test_blockhash_usual_even() {
        let block_number = U256::from(1200); // right_tag = 1
        let stack = Stack::from_slice(&[block_number]);
        let block_idx = 1;
        let mut block_hash_list = HashMap::new();
        for i in 1001..=1260 {
            block_hash_list.insert(i, U256::from(i));
        }

        let hash = U256::from_str_radix(
            "0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470",
            16,
        )
        .unwrap();
        block_hash_list.insert(1200, hash);

        run(stack.clone(), block_idx, block_hash_list.clone(), hash);
    }

    // blocknumber out of u64 range
    #[test]
    fn test_blockhash_overflow_0() {
        let block_number = U256::from(u128::MAX);
        let stack = Stack::from_slice(&[block_number]);
        let block_idx = 10;
        let mut block_hash_list = HashMap::new();
        for i in 1001..=1260 {
            block_hash_list.insert(i, U256::from(i));
        }
        // return 0
        let hash = U256::from_str_radix("0x0", 16).unwrap();

        run(stack.clone(), block_idx, block_hash_list.clone(), hash);
    }

    // blocknumber less than block_number_cur - 256
    #[test]
    fn test_blockhash_overflow_1() {
        let block_number = U256::from(100);
        let stack = Stack::from_slice(&[block_number]);
        let block_idx = 1;
        let mut block_hash_list = HashMap::new();
        for i in 1001..=1260 {
            block_hash_list.insert(i, U256::from(i));
        }
        // return 0
        let hash = U256::from_str_radix("0x0", 16).unwrap();

        run(stack.clone(), block_idx, block_hash_list.clone(), hash);
    }

    // blocknumber greater than block_number_cur
    #[test]
    fn test_blockhash_overflow_2() {
        let block_number = U256::from(2004);
        let stack = Stack::from_slice(&[block_number]);
        let block_idx = 1;
        let mut block_hash_list = HashMap::new();
        for i in 1001..=1260 {
            block_hash_list.insert(i, U256::from(i));
        }
        // return 0
        let hash = U256::from_str_radix("0x0", 16).unwrap();

        run(stack.clone(), block_idx, block_hash_list.clone(), hash);
    }
}
