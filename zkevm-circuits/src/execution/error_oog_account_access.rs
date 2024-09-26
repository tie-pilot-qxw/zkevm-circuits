// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation::get_lt_operations;
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::ExpressionOutcome;
use crate::witness::arithmetic::{self, Tag};
use crate::witness::state;
use crate::{
    constant::NUM_AUXILIARY,
    execution::{
        end_call_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
        ExecutionGadget, ExecutionState,
    },
    util::query_expression,
    witness::assign_or_panic,
};
use core::panic;
use eth_types::evm_types::GasCost;
use eth_types::U256;
use eth_types::{evm_types::OpcodeId, Field, GethExecStep};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{select, Expr};

use crate::arithmetic_circuit::operation;

use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const TAG_BALANCE_OFFSET: usize = 0;
const TAG_EXTCODEHASH_OFFSET: usize = 1;
const TAG_EXTCODESIZE_OFFSET: usize = 2;
const GAS_LEFT_LT_GAS_COST: usize = 24;
const GAS_LEFT_LT_GAS_COST_DIFF: usize = 25;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;

/// ErrorOutOfGasAccountAccess overview:
/// pop a value from the top of the stack: address,
/// failed to get the corresponding value according to the address,
/// because of insufficient gas
///
/// ErrorOutOfGasAccountAccess Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// WARM_R(12 columns) means is_warm_read lookup,
/// WARM_W(12 columns) means is_warm_write lookup
/// GC(1 column,index 24) means gas_left < gas_cost ,if true 1, else 0
/// GD(1 column,index 25) means gas_left - gas_cost
/// TCO(1 column) means opcode is BALANCE
/// THO(1 column) means opcode is EXTCODEHASH
/// TEO(1 column) means opcode is EXTCODESIZE
/// STATE1(8 columns) means state table lookup(pop)
/// ARITH(start at column index 10, occupy 5 columns) means arithmetic u64overflow lookup
/// +---+-------+-------+-------+-------------+
/// |cnt| 8 col | 8 col | 8 col |  8 col      |
/// +---+-------+-------+-------+-------------+
/// | 2 | WARM_R | WARM_W |     |GC|GD|       |
/// | 1 | STATE1 |   |ARITH|    |             |
/// | 0 | DYNA_SELECTOR   | AUX |TCO|THO|TEO| |
/// +---+-------+-------+-------+-------------+

pub struct ErrorOutOfGasAccountAccess<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ErrorOutOfGasAccountAccess<F>
{
    fn name(&self) -> &'static str {
        "ERROR_OUT_OF_GAS_ACCOUNT_ACCESS"
    }

    fn execution_state(&self) -> super::ExecutionState {
        ExecutionState::ERROR_OUT_OF_GAS_ACCOUNT_ACCESS
    }

    fn num_row(&self) -> usize {
        NUM_ROW
    }

    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, end_call_1::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &super::ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut halo2_proofs::plonk::VirtualCells<F>,
    ) -> Vec<(String, halo2_proofs::plonk::Expression<F>)> {
        let mut constraints = vec![];

        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        let is_balance = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_BALANCE_OFFSET],
            Rotation::cur(),
        );
        let is_extcodehash = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_EXTCODEHASH_OFFSET],
            Rotation::cur(),
        );
        let is_extcodesize = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_EXTCODESIZE_OFFSET],
            Rotation::cur(),
        );
        let selector = SimpleSelector::new(&[
            is_balance.clone(),
            is_extcodehash.clone(),
            is_extcodesize.clone(),
        ]);
        constraints.extend(selector.get_constraints());

        let entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            entry.clone(),
            0,
            NUM_ROW,
            0.expr(),
            false,
        ));
        let (_, _, address_hi, address_lo, _, _, _, _) = extract_lookup_expression!(state, entry);

        // storage lookup constraints
        let mut is_warm = 0.expr();
        for i in 0..2 {
            let entry = config.get_storage_lookup(meta, i, Rotation(-2));
            let mut is_write = true;
            if i == 0 {
                let extracted = extract_lookup_expression!(storage, entry.clone());
                is_warm = extracted.3;
                is_write = false;
            }
            constraints.append(&mut config.get_storage_full_constraints_with_tag(
                meta,
                entry,
                i + 1,
                NUM_ROW,
                0.expr(),
                0.expr(),
                address_hi.clone(),
                address_lo.clone(),
                state::Tag::AddrInAccessListStorage,
                is_write,
            ))
        }

        // compute gas cost
        let gas_cost = select::expr(
            is_warm,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let current_gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let lt = meta.query_advice(config.vers[GAS_LEFT_LT_GAS_COST], Rotation(-2));
        let lt_diff = meta.query_advice(config.vers[GAS_LEFT_LT_GAS_COST_DIFF], Rotation(-2));
        let gas_left_lt_gas_cost: SimpleLtGadget<F, 8> =
            SimpleLtGadget::new(&current_gas_left, &gas_cost, &lt, &lt_diff);
        constraints.extend(gas_left_lt_gas_cost.get_constraints());

        let (tag, [diff_hi, diff_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 2, Rotation::prev())
        );
        let diff_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "diff_u64_overflow".into());
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (Tag::U64Overflow as u8).expr(),
            ),
            ("diff_hi == 0".into(), diff_hi.clone()),
            ("diff_lo = lt_diff".into(), diff_lo - lt_diff.clone()),
            (
                "diff not overflow".into(),
                1.expr() - diff_not_overflow.expr(),
            ),
        ]);

        // pc no change
        constraints.extend(
            config.get_next_single_purpose_constraints(meta, CoreSinglePurposeOutcome::default()),
        );
        // next execution state should be END_CALL_1
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::END_CALL_1, end_call_1::NUM_ROW, None)],
                None,
            ),
        ));
        constraints.extend([
            // opcode constraint
            (
                "opcode is BALANCE, EXTCODEHASH, EXTCODESIZE".into(),
                opcode
                    - selector.select(&[
                        OpcodeId::BALANCE.as_u8().expr(),
                        OpcodeId::EXTCODEHASH.as_u8().expr(),
                        OpcodeId::EXTCODESIZE.as_u8().expr(),
                    ]),
            ),
            // gas left constraint
            ("gas left < gas cost".into(), lt - 1.expr()),
        ]);
        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        constraints
    }

    fn get_lookups(
        &self,
        config: &super::ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut halo2_proofs::plonk::ConstraintSystem<F>,
    ) -> Vec<(String, crate::table::LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let is_warm_read = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-2))
        });
        let is_warm_write = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-2))
        });
        let u64_overflow = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 2, Rotation::prev())
        });
        vec![
            (
                "error_out_of_gas_account_access_stack_lookup_0".into(),
                stack_lookup_0,
            ),
            (
                "error_out_of_gas_account_is_warm_read_lookup".into(),
                is_warm_read,
            ),
            (
                "error_out_of_gas_account_is_warm_write_lookup".into(),
                is_warm_write,
            ),
            (
                "error_out_of_gas_account_u64_overflow_lookup".into(),
                u64_overflow,
            ),
        ]
    }

    fn gen_witness(
        &self,
        trace: &GethExecStep,
        current_state: &mut crate::witness::WitnessExecHelper,
    ) -> crate::witness::Witness {
        assert!(
            trace.op == OpcodeId::BALANCE
                || trace.op == OpcodeId::EXTCODEHASH
                || trace.op == OpcodeId::EXTCODESIZE
        );
        current_state.return_success = false;
        let (stack_pop_0, address) = current_state.get_pop_stack_row_value(&trace);

        // check address is warm for gas
        let (is_warm_read, is_warm) = current_state.get_addr_access_list_read_row(address);
        let is_warm_write = current_state.get_addr_access_list_write_row(address, true, is_warm);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_storage_lookups([&is_warm_read, &is_warm_write]);

        // compute gas cost
        let current_gas_left = current_state.gas_left;
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        };
        // compute lt,diff
        let (gas_left_lt_gas_cost, diff, _) = get_lt_operations(
            &current_gas_left.into(),
            &gas_cost.into(),
            &U256::from(2).pow(U256::from(64)),
        );
        assign_or_panic!(
            core_row_2[GAS_LEFT_LT_GAS_COST],
            (gas_left_lt_gas_cost as u8).into()
        );
        assign_or_panic!(core_row_2[GAS_LEFT_LT_GAS_COST_DIFF], diff.clone());
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0.clone()]);
        // insert diff overflow
        let (u64_overflow_rows, _) = operation::u64overflow::gen_witness::<F>(vec![diff.into()]);
        core_row_1.insert_arithmetic_tiny_lookup(2, &u64_overflow_rows);

        let mut core_row_0 = ExecutionState::ERROR_OUT_OF_GAS_ACCOUNT_ACCESS
            .into_exec_state_core_row(trace, current_state, NUM_STATE_HI_COL, NUM_STATE_LO_COL);
        let tag = match trace.op {
            OpcodeId::BALANCE => 0,
            OpcodeId::EXTCODEHASH => 1,
            OpcodeId::EXTCODESIZE => 2,
            _ => panic!("error out of gas account access, expect opcode is BALANCE, EXTCODEHASH or EXTCODESIZE"),
        };

        simple_selector_assign(
            &mut core_row_0,
            [
                NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_BALANCE_OFFSET,
                NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_EXTCODEHASH_OFFSET,
                NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + TAG_EXTCODESIZE_OFFSET,
            ],
            tag,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );
        crate::witness::Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, is_warm_read, is_warm_write],
            arithmetic: u64_overflow_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ErrorOutOfGasAccountAccess {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::GAS_LEFT_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use crate::execution::ExecutionConfig;
    use crate::keccak_circuit::keccak_packed_multi::calc_keccak;
    use crate::witness::Witness;
    use crate::witness::WitnessExecHelper;
    use eth_types::Bytecode;
    use halo2_proofs::plonk::{ConstraintSystem, Expression};
    use std::collections::HashMap;

    generate_execution_gadget_test_circuit!();

    fn run(
        stack: Stack,
        code_addr: U256,
        bytecode: HashMap<U256, Bytecode>,
        stack_top: U256,
        op: OpcodeId,
        is_warm: bool,
    ) {
        let stack_pointer = stack.0.len();
        let gas_consumed = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        };

        let mut current_state = WitnessExecHelper {
            code_addr,
            bytecode,
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: gas_consumed - 1,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left;
        let mut trace = prepare_trace_step!(0, op, stack, Some(String::from("out of gas")));
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = trace.pc.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_out_of_gas() {
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let stack = Stack::from_slice(&[code_addr]);
        let mut bytecode = HashMap::new();
        let hex_code = hex::decode("6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea2646970667358fe1220fe7840966036100a633d188b84e1a14545ddea09878db189eb4a567d852807dd64736f6c63430008150033").unwrap();
        let code = Bytecode::from(hex_code.clone());
        bytecode.insert(code_addr, code);
        let hash = calc_keccak(hex_code.as_slice());
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::BALANCE,
            false,
        );
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::BALANCE,
            true,
        );
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODEHASH,
            false,
        );
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODEHASH,
            true,
        );
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODESIZE,
            false,
        );
        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODESIZE,
            true,
        );
    }
}
