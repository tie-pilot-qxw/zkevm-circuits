// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::{GasCost, OpcodeId, GAS_STIPEND_CALL_WITH_VALUE};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{select, Expr};

use crate::arithmetic_circuit::operation;
use crate::constant::{
    NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
    STORAGE_COLUMN_WIDTH, TRACE_GAS_COST_IDX, TRACE_GAS_IDX,
};
use crate::execution::storage::get_multi_inverse;
use crate::execution::ExecutionState::{CALL_4, CALL_6};
use crate::execution::{
    call_6, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::{MemoryExpansion, U64Div, U64Overflow};
use crate::witness::state::Tag::AddrInAccessListStorage;
use crate::witness::{assign_or_panic, state, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 4;
const STATE_STAMP_DELTA: usize = 5;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at post_call
const STATE_LOOKUP_IDX: usize = 0;
const STAMP_INIT_COL: usize = NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY;
const GAS_COL: usize = STAMP_INIT_COL + TRACE_GAS_IDX;
const GAS_COST_COL: usize = STAMP_INIT_COL + TRACE_GAS_COST_IDX;
const OPCODE_SELECTOR_IDX: usize = GAS_COST_COL + 1;
const OPCODE_SELECTOR_IDX_START: usize = 0;

/// call_5 前一个指令为call_4,后一个指令为call_6， call_5用于计算call最终的gas费用
/// call_5 需要参数为三个栈元素，一个存储元素：
/// - gas: 用于计算callGas;
/// - addr: 用于判断访问地址是否为空账户（暂时未实现）；
/// - value: 用于判断value是否为0，来决定gas计费；
/// - is_warm: EIP2929增加的计费规则;
///
/// Table layout:
///     cnt = 0, trace gas and trace gas cost for next gadget;
///     cnt = 1, STATE0, STATE1, STATE2 represent gas, addr, and value respectively.
///     cnt = 2:
///         1. U64Div is available_gas / 64;
///         2. U64Overflow is gas_in_stack overflow constraints;
///         3. U64Overflow is gas_left overflow constraints;
///         4. MemoryExpansion is gas_in_stack < available_gas constraints;
///     cnt = 3:
///         1. STORAGE_READ is read is_warm;
///         2. STORAGE_WRITE is write is_warm to TRUE;
///         3. value_inv is `value == zero` required parameters;
///         4. capped_gas_left is lower degree required parameters;
///         
/// +-----+-------------------+---------------------+---------------------+------------------------+--------------------+--------------------------+
/// | cnt |                   |                     |                     |                        |                    |                          |
/// +-----+-------------------+---------------------+---------------------+------------------------|--------------------+--------------------------+
/// | 3   | STORAGE_READ(0..11)| STORAGE_WRITE(12..23)| value_inv(24)     | capped_gas_left(25)    |                    |                          |
/// | 2   | U64Div(2..6)      | U64Overflow(7..11)  | U64Overflow(12..16) | MemoryExpansion(17..21)|                    |                          |
/// | 1   | STATE0(0..7)      | STATE1(8..15)       | STATE2(16..23)      |                        |                    |                          |
/// | 0   | DYNAMIC(0..17)    | AUX(18..24)         |   STAMP_INIT(25)    | TRACE_GAS(26)          | TRACE_GAS_COST(27) |  OPCODE_SELECTOR(28..30) |
/// +-----+-------------------+---------------------+---------------------+------------------------|--------------------+--------------------------+

pub struct Call5Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call5Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_5"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_5
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_6::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let mut constraints = vec![];

        // Create a simple selector with opcode
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 1], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_SELECTOR_IDX + 2], Rotation::cur()),
        ]);
        // Add constraints for the selector.
        constraints.extend(selector.get_constraints());

        // stack constraints
        let mut operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, STATE_LOOKUP_IDX + i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                -i.expr(),
                false,
            ));

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        // constraints state entry[2]
        let entry = config.get_state_lookup(meta, STATE_LOOKUP_IDX + 2);
        constraints.extend(config.get_read_value_constraints_by_call(
            meta,
            entry.clone(),
            NUM_ROW,
            &selector,
            STATE_LOOKUP_IDX + 2,
        ));
        let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, entry);
        operands.push([value_hi, value_lo]);

        // STATICCALL only performs one write operation，while CALL and STATICCALL both perform one read operation and one write operation.
        let mut is_warm: Expression<F> = 0.expr();
        let lookups = [
            (
                0,
                Rotation(-3),
                3,
                selector.select(&[3.expr(), 2.expr(), 3.expr()]),
                false, // is_warm read
            ),
            (
                1,
                Rotation(-3),
                4,
                selector.select(&[4.expr(), 3.expr(), 4.expr()]),
                true, // is_warm write
            ),
        ];

        for (num, rotation, index, stamp_delta, is_write) in lookups {
            let entry = config.get_storage_lookup(meta, num, rotation);
            constraints.extend(config.get_storage_full_constraints_with_tag_stamp_delta(
                meta,
                entry.clone(),
                index,
                NUM_ROW,
                0.expr(),
                0.expr(),
                operands[1][0].clone(),
                operands[1][1].clone(),
                AddrInAccessListStorage,
                stamp_delta.clone(),
                is_write,
            ));
            let extracted = extract_lookup_expression!(storage, entry);
            if num == 0 {
                is_warm = extracted.3;
            }
        }

        let value_inv = meta.query_advice(config.vers[2 * STORAGE_COLUMN_WIDTH], Rotation(-3));
        let value_is_zero = SimpleIsZero::new(
            &(operands[2][0].clone() + operands[2][1].clone()),
            &value_inv,
            "value_is_zero".into(),
        );
        constraints.extend(value_is_zero.get_constraints());

        let base_gas = select::expr(
            is_warm,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        ) + (1.expr() - value_is_zero.expr())
            * (GasCost::CALL_WITH_VALUE.expr()
            // todo 暂时还没实现account为空的情况，用0来代替，我们目前account都不会为空
            +  0.expr() * GasCost::NEW_ACCOUNT.expr());

        let memory_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );

        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let gas_left_before_exec = meta.query_advice(gas_left, Rotation(-1 * NUM_ROW as i32));
        let available_gas =
            gas_left_before_exec.clone() - base_gas.clone() - memory_gas_cost.clone();

        let (tag, [one_64th_numerator, one_64th_denominator, available_gas_one_64th, _]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));
        constraints.extend([
            ("tag is U64Div".into(), tag - (U64Div as u8).expr()),
            (
                "one_64th_numerator = available_gas".into(),
                one_64th_numerator - available_gas.clone(),
            ),
            (
                "one_64th_denominator".into(),
                one_64th_denominator - 64.expr(),
            ),
        ]);

        let all_but_one_64th_gas = available_gas - available_gas_one_64th;

        let (tag, [gas_input_hi, gas_input_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 1));
        // stack里的gas不一定是U64
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            (
                "gas_input_hi == gas_in_stack_hi".into(),
                gas_input_hi.clone() - operands[0][0].clone(),
            ),
            (
                "gas_input_lo = gas_in_stack_lo".into(),
                gas_input_lo.clone() - operands[0][1].clone(),
            ),
        ]);

        let gas_in_stack_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "u64_overflow".into());
        constraints.extend(gas_in_stack_not_overflow.get_constraints());

        let (lt_tag, [all_but_one_64th_gas_mul_32, gas_in_stack_input, lt, _]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 3));

        // 判断all_but_one_64th_gas是否小于gas_in_stack
        constraints.extend([
            (
                "lt_tag is MemoryExpansion".into(),
                lt_tag - (MemoryExpansion as u8).expr(),
            ),
            (
                "all_but_one_64th_gas_mul_32 = all_but_one_64th_gas * 32".into(),
                all_but_one_64th_gas_mul_32 - all_but_one_64th_gas.clone() * 32.expr(),
            ),
            (
                "gas_in_stack_input = gas_in_stack".into(),
                gas_in_stack_input - operands[0][1].clone(),
            ),
            ("lt is bool".into(), lt.clone() * (1.expr() - lt.clone())),
        ]);

        // lower degree
        // if lt == 1, gas_in_stack < all_but_one_64th_gas
        // if lt == 0, gas_in_stack >= all_but_one_64th_gas
        let capped_gas_left = select::expr(
            lt.expr(),
            operands[0][1].clone(),
            all_but_one_64th_gas.clone(),
        );
        let capped_gas_left_in_table =
            meta.query_advice(config.vers[2 * STORAGE_COLUMN_WIDTH + 1], Rotation(-3));
        constraints.push((
            "capped_gas_left = capped_gas_left_in_table".into(),
            capped_gas_left.clone() - capped_gas_left_in_table.clone(),
        ));

        let call_gas = select::expr(
            gas_in_stack_not_overflow.expr(),
            capped_gas_left_in_table,
            all_but_one_64th_gas,
        );

        let current_gas_left = meta.query_advice(gas_left, Rotation::cur());

        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 2));
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "u64_overflow".into());
        constraints.extend(gas_left_not_overflow.get_constraints());

        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            // 我们最后剩余的gas_left，输入时的高128bit一定要求是0。
            ("gas_left_hi == 0".into(), gas_left_hi.clone()),
            (
                "gas_left_lo = current_gas_left".into(),
                gas_left_lo - current_gas_left.clone(),
            ),
            (
                "gas_left not overflow".into(),
                1.expr() - gas_left_not_overflow.expr(),
            ),
        ]);

        // call_5 core constraints
        let state_stamp_init =
            meta.query_advice(config.vers[STAMP_INIT_COL], Rotation(-1 * NUM_ROW as i32));
        let stamp_init_for_next_gadget =
            meta.query_advice(config.vers[STAMP_INIT_COL], Rotation::cur());

        let trace_gas_for_next_gadget = meta.query_advice(config.vers[GAS_COL], Rotation::cur());
        let trace_gas_cost_for_next_gadget =
            meta.query_advice(config.vers[GAS_COST_COL], Rotation::cur());

        let gas_cost = base_gas.clone() + memory_gas_cost.clone() + call_gas.clone();
        constraints.extend([
            (
                // append constraint for the next execution state's stamp_init
                "state_init_for_next_gadget correct".into(),
                stamp_init_for_next_gadget - state_stamp_init,
            ),
            // trace.gas and trace.gas_cost for next
            (
                "trace_gas_for_next_gadget correct".into(),
                trace_gas_for_next_gadget - gas_left_before_exec,
            ),
            (
                "trace_gas_cost_for_next_gadget correct".into(),
                trace_gas_cost_for_next_gadget - gas_cost,
            ),
        ]);

        let state_stamp_dela = selector.select(&[
            STATE_STAMP_DELTA.expr(),
            (STATE_STAMP_DELTA - 1).expr(),
            STATE_STAMP_DELTA.expr(),
        ]);
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(state_stamp_dela),
            refund: ExpressionOutcome::Delta(0.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // todo 当account不为空的时候(目前没有实现，默认都是不为空)，当前的gas_left应该等于call_gas; 当为空时，下一个状态此时相当于还在主合约流程中，此时的current_gas_left计算规则与此不同
            gas_left: ExpressionOutcome::To(call_gas),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta.clone()));

        constraints.push((
            "opcode".into(),
            opcode
                - selector.select(&[
                    OpcodeId::CALL.as_u8().expr(),
                    OpcodeId::STATICCALL.as_u8().expr(),
                    OpcodeId::DELEGATECALL.as_u8().expr(),
                ]),
        ));
        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome::default();
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // prev state is call_5
        // next state is CALL_6
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![CALL_4],
                NUM_ROW,
                vec![(CALL_6, call_6::NUM_ROW, None)],
                None,
            ),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));

        let storage_lookup_read = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-3))
        });
        let storage_lookup_write = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-3))
        });
        let u64_div = query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        let gas_in_stack_u64_overflow =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 1));
        let gas_left_u64_overflow =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 2));
        let memory_expansion =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 3));

        vec![
            ("call_5 stack read gas".into(), stack_lookup_0),
            ("call_5 stack read addr".into(), stack_lookup_1),
            ("call_5 stack read value".into(), stack_lookup_2),
            ("call_5 storage read warm".into(), storage_lookup_read),
            ("call_5 storage write warm".into(), storage_lookup_write),
            ("call_5 u64 div".into(), u64_div),
            (
                "call_5 gas_in_stack u64 overflow".into(),
                gas_in_stack_u64_overflow,
            ),
            ("call_5 gas_left u64 overflow".into(), gas_left_u64_overflow),
            ("call_5 memory expansion".into(), memory_expansion),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_read_0, gas_in_stack) = current_state.get_peek_stack_row_value(trace, 1);
        let (stack_read_1, addr) = current_state.get_peek_stack_row_value(trace, 2);

        let ((state_read_value_row, value), selector_index) = match trace.op {
            OpcodeId::CALL => (
                current_state.get_peek_stack_row_value(trace, 3),
                OPCODE_SELECTOR_IDX_START,
            ),
            OpcodeId::STATICCALL => (
                (state::Row::default(), U256::zero()),
                OPCODE_SELECTOR_IDX_START + 1,
            ),
            OpcodeId::DELEGATECALL => {
                let parent_value = *current_state.value.get(&current_state.call_id).unwrap();
                let call_context_read_row = current_state
                    .get_call_context_read_row_with_arbitrary_tag(
                        state::CallContextTag::Value,
                        parent_value,
                        current_state.call_id,
                    );
                (
                    (call_context_read_row, parent_value),
                    OPCODE_SELECTOR_IDX_START + 2,
                )
            }
            _ => panic!("opcode not CALL or STATICCALL or DELEGATECALL"),
        };
        let (storage_read, is_warm) = current_state.get_addr_access_list_read_row(addr);
        let storage_write = current_state.get_addr_access_list_write_row(addr, true, is_warm);

        let value_inv = get_multi_inverse::<F>(value);
        let callee_code_length = current_state.bytecode.get(&addr).unwrap().code().len();
        // part1. base gas cost
        // constraints:
        //  1.is_warm lookup
        //  2.value is zero constraints
        //  3.todo callee_code is empty constraints,目前我们callee bytecode都不为空，可以忽略这个约束
        let mut gas = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        } + if !value.is_zero() {
            GasCost::CALL_WITH_VALUE
                // todo 此处应为address对应的account是否存在，也即nonce、balance、codehash为空
                + if callee_code_length == 0 {
                GasCost::NEW_ACCOUNT
            } else {
                0
            }
        } else {
            0
        };

        // part2. memory gas cost
        gas = gas + current_state.memory_gas_cost;
        // 使用完后可以重置，防止下一次CALL误计算
        current_state.memory_gas_cost = 0;

        // part3. callGas
        // constraints:
        //  1.available_gas 1/64 arithemetic
        //  2.u64overflow constraints
        //  3.available_gas < gas_in_stack compare
        let mut available_gas = trace.gas - gas;
        let (u64_div_row, result) =
            operation::u64div::gen_witness(vec![U256::from(available_gas), U256::from(64)]);

        available_gas = available_gas - result[0].as_u64();

        // 此条件下 gas_in_stack是U64
        // 使用memory_expansion可以完成两个U64数的比较，可以节省cells
        // input: [U256::from(available_gas) * 32, gas_in_stack]，因为memory_expansion中会做32位对齐除法，传参时先乘32；
        // res[0] == 1, gas_in_stack < res[1] = available_gas
        // res[0] == 0, gas_in_stack >= res[1] = available_gas
        let (lt_row, res) = operation::memory_expansion::gen_witness(vec![
            U256::from(available_gas) * 32,
            gas_in_stack,
        ]);

        let (gas_in_stack_u64_overflow_row, result) =
            operation::u64overflow::gen_witness::<Fr>(vec![gas_in_stack]);
        let capped_gas_left = if res[0].is_zero() {
            available_gas
        } else {
            gas_in_stack.as_u64()
        };
        let call_func_gas = if result[0].is_zero() {
            capped_gas_left
        } else {
            available_gas
        };

        // part4. select gas left
        if callee_code_length != 0 {
            current_state.gas_left = call_func_gas
        } else {
            // 目前不会走到这个分支，因为我们code_len不为空
            current_state.gas_left = trace.gas - gas + GAS_STIPEND_CALL_WITH_VALUE;
        }

        let (gas_left_u64_overflow_row, result) =
            operation::u64overflow::gen_witness::<Fr>(vec![U256::from(current_state.gas_left)]);
        assert_eq!(result[0].is_zero(), true);

        let mut core_row_3 = current_state.get_core_row_without_versatile(trace, 3);
        core_row_3.insert_storage_lookups([&storage_read, &storage_write]);
        assign_or_panic!(core_row_3[2 * STORAGE_COLUMN_WIDTH], value_inv);
        // in constraints:
        // let capped_gas_left = select::expr(less.expr(), available_gas.clone(), operands[0][1].clone());
        // let call_gas = select::expr(
        //      gas_in_stack_not_overflow.expr(),
        //      capped_gas_left_in_table,
        //      available_gas,
        // );
        // call_gas degree is 10, because capped_gas_left is 8, when multiple with other expression, it will be 10
        assign_or_panic!(
            core_row_3[2 * STORAGE_COLUMN_WIDTH + 1],
            capped_gas_left.into()
        );

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_arithmetic_tiny_lookup(0, &u64_div_row);
        core_row_2.insert_arithmetic_tiny_lookup(1, &gas_in_stack_u64_overflow_row);
        core_row_2.insert_arithmetic_tiny_lookup(2, &gas_left_u64_overflow_row);
        core_row_2.insert_arithmetic_tiny_lookup(3, &lt_row);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([&stack_read_0, &stack_read_1, &state_read_value_row]);

        let mut core_row_0 = ExecutionState::CALL_5.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(core_row_0[STAMP_INIT_COL], stamp_init.into());
        assign_or_panic!(core_row_0[GAS_COL], trace.gas.into());
        assign_or_panic!(core_row_0[GAS_COST_COL], trace.gas_cost.into());

        // opcodeid selector
        simple_selector_assign(
            &mut core_row_0,
            [
                OPCODE_SELECTOR_IDX,
                OPCODE_SELECTOR_IDX + 1,
                OPCODE_SELECTOR_IDX + 2,
            ],
            selector_index,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let state_rows = if trace.op == OpcodeId::STATICCALL {
            vec![stack_read_0, stack_read_1, storage_read, storage_write]
        } else {
            vec![
                stack_read_0,
                stack_read_1,
                state_read_value_row,
                storage_read,
                storage_write,
            ]
        };
        let mut arithmetic = vec![];
        arithmetic.extend(u64_div_row);
        arithmetic.extend(gas_in_stack_u64_overflow_row);
        arithmetic.extend(gas_left_u64_overflow_row);
        arithmetic.extend(lt_row);

        Witness {
            core: vec![core_row_3, core_row_2, core_row_1, core_row_0],
            state: state_rows,
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call5Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use eth_types::Bytecode;

    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[
            0x05.into(),
            0x2222.into(),
            0x04.into(),
            0x1111.into(),
            0x01.into(),
            0x1234.into(),
            0x07.into(),
        ]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            gas_left: 0x07,
            ..WitnessExecHelper::new()
        };
        let state_stamp_init = 3;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;
        let code_addr = U256::from_str_radix("0x1234", 16).unwrap();
        let mut bytecode = HashMap::new();
        // 32 byte
        let code = Bytecode::from(
            hex::decode("7c00000000000000000000000000000000000000000000000000000000005038")
                .unwrap(),
        );
        bytecode.insert(code_addr, code);
        current_state.bytecode = bytecode;

        let mut trace = prepare_trace_step!(0, OpcodeId::CALL, stack);
        trace.gas = 0x254023;
        // 此测试用例计算出的gas_cost
        trace.gas_cost = 0x2D57;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_4.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(U256::from(state_stamp_init));
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(U256::from(0x254023));
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_6.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            //row.pc = 0.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }
}
