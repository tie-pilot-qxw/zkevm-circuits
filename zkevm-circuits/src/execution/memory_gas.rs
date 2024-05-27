use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{select, Expr};

use crate::arithmetic_circuit::operation;
use crate::constant::{
    GAS_LEFT_IDX, MEMORY_CHUNK_PREV_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY, NUM_VERS,
};
use crate::execution::{
    log_gas, memory_copier_gas, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::{MemoryExpansion, U64Div};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 0;

const CORE_ROW_1_START_COL_IDX: usize = 17;

/// memory_gas
/// 前一个指令对应：CALLDATACOPY, CODECOPY, RETURNDATACOPY, EXTCODECOPY, MLOAD, MSTORE, MSTORE8, RETURN, REVERT, LOG0-4
/// 后一个指令对应：MEMORY_COPIER_GAS, PURE_MEMORY_GAS, LOG_GAS
///
/// Table layout:
///     cnt = 0:
///         1.MEMORY_GAS(26) is the gas cost calculated for the current state and reserves space for the next state in advance.
///         2.NEXT_IS_LOG_GAS(29) is set to 1 if the next state is LOG_GAS.
///         3.NEXT_IS_PURE_MEMORY_GAS(30) is set to 1 if the next state is PURE_MEMORY_GAS.
///         4.NEXT_IS_MEMORY_COPIER_GAS(31) is set to 1 if the next state is MEMORY_COPIER_GAS.
///     cnt = 1:
///         1. MEMORY_EXPANSION is `Max(cur_memory_size, memory_size)`;
///         2. U64Div is `cur_memory_size * cur_memory_size / 512 = curr_quad_memory_cost`;
///         3. U64Div is `next_memory_size * next_memory_size / 512 = next_quad_memory_cost`;
///         4. SELECTOR is the opcode selector.
///
/// +-----+------------------------+----------------+----------------+----------------+------------------------------+-----------------------------+-----------------------------+
/// | cnt |                        |                |                |                |                              |                             |                             |
/// +-----+------------------------+----------------+----------------+----------------+------------------------------+-----------------------------+-----------------------------+
/// | 1   | MEMORY_EXPANSION(2..6) | U64DIV(7..11) | U64DIV(12..16) | SELECTOR(17..30)|                              |                             |                             |
/// | 0   | DYNAMIC(0..17)         | AUX(18..24)   |                | MEMORY_GAS(26)  |   NEXT_IS_LOG_GAS(29)        |NEXT_IS_PURE_MEMORY_GAS(30)  |NEXT_IS_MEMORY_COPIER_GAS(31)|
/// +-----+------------------------+----------------+----------------+----------------+------------------------------+-----------------------------+-----------------------------+

pub struct MemoryGasGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for MemoryGasGadget<F>
{
    fn name(&self) -> &'static str {
        "MEMORY_GAS"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::MEMORY_GAS
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, memory_copier_gas::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        let memory_size = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );
        // Max(cur_memory_word_size, max_word_size) = next_word_size
        let memory_chunk_prev = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + MEMORY_CHUNK_PREV_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );

        // input: [memory_size, memory_chunk_prev]
        let (next_word_tag, [memory_size_input, curr_word_size, lt, memory_word_size]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        );

        let next_word_size =
            select::expr(lt.clone(), memory_word_size.clone(), curr_word_size.clone());

        // cur_memory_word_size * cur_memory_word_size / 512 = curr_quad_memory_cost
        let (
            curr_quad_memory_cost_tag,
            [cur_memory_size_numerator, cur_memory_size_denominator, curr_quad_memory_cost, _],
        ) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 1, Rotation::prev())
        );

        // next_memory_size * next_memory_size / 512 = next_quad_memory_cost
        let (
            next_quad_memory_cost_tag,
            [next_memory_size_numerator, next_memory_size_denominator, next_quad_memory_cost, _],
        ) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 2, Rotation::prev())
        );

        // stack, arithmetic input, tag constraints
        constraints.extend([
            // Max(cur_memory_word_size, max_word_size) = next_word_size
            // tag: MemoryExpansion
            // input: [cur_memory_word_size * 32, max_word_size]
            // output: lt (bool), cur_memory_word_size
            // note, cur_memory_word_size use lookup constraints
            (
                "next_word_tag is MemoryExpansion".to_string(),
                next_word_tag - (MemoryExpansion as u8).expr(),
            ),
            (
                "memory_size_input == memory_size".into(),
                memory_size_input - memory_size,
            ),
            (
                "curr_word_size == memory_chunk".into(),
                curr_word_size - memory_chunk_prev.clone(),
            ),
            // cur_memory_word_size * cur_memory_word_size / 512 = curr_quad_memory_cost
            // tag: U64DIV
            // input: [cur_memory_size, 512]
            // output: [curr_quad_memory_cost]
            // note: curr_quad_memory_cost use lookup constraints
            (
                "curr_quad_memory_cost_tag is U64DIV".to_string(),
                curr_quad_memory_cost_tag - (U64Div as u8).expr(),
            ),
            (
                "cur_memory_size_numerator == memory_chunk_prev * memory_chunk_prev".into(),
                cur_memory_size_numerator - memory_chunk_prev.clone() * memory_chunk_prev.clone(),
            ),
            (
                "next_memory_size_denominator == 512".into(),
                next_memory_size_denominator - 512.expr(),
            ),
            // next_memory_word_size * next_memory_word_size / 512 = next_quad_memory_cost
            // tag: U64DIV
            // input: [next_word_size, 512]
            // output: [next_quad_memory_cost]
            // note: next_quad_memory_cost use lookup constraints
            (
                "next_quad_memory_cost_tag is U64DIV".to_string(),
                next_quad_memory_cost_tag - (U64Div as u8).expr(),
            ),
            (
                "next_memory_size_numerator == next_word_size * next_word_size".into(),
                next_memory_size_numerator - next_word_size.clone() * next_word_size.clone(),
            ),
            (
                "cur_memory_size_denominator == 512".into(),
                cur_memory_size_denominator - 512.expr(),
            ),
        ]);

        // gas_cost constraint
        let gas_cost = GasCost::MEMORY_EXPANSION_LINEAR_COEFF.expr()
            * (next_word_size - memory_chunk_prev)
            + (next_quad_memory_cost - curr_quad_memory_cost);
        let memory_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation::cur(),
        );
        constraints.push(("gas cost".to_string(), gas_cost - memory_gas_cost));

        // core constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // todo 后续实现中加入所有可能的opcode
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 3], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 4], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 5], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 6], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 7], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 8], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 9], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 10], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 11], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 12], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 13], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());
        constraints.push((
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::CALLDATACOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::CODECOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::RETURNDATACOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::EXTCODECOPY.as_u8().expr(),
                opcode.clone() - OpcodeId::MLOAD.as_u8().expr(),
                opcode.clone() - OpcodeId::MSTORE.as_u8().expr(),
                opcode.clone() - OpcodeId::MSTORE8.as_u8().expr(),
                opcode.clone() - OpcodeId::RETURN.as_u8().expr(),
                opcode.clone() - OpcodeId::REVERT.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG0.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG1.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG2.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG3.as_u8().expr(),
                opcode.clone() - OpcodeId::LOG4.as_u8().expr(),
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

        // CALLDATACOPY, CODECOPY, RETURNDATACOPY, EXTCODECOPY 下一个状态对应memory_copier_gas
        let following_memory_copier_gas = selector.select(&[
            1.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        ]);
        let next_is_memory_copier_gas =
            meta.query_advice(config.vers[NUM_VERS - 1], Rotation::cur());

        // MLOAD, MSTORE, MSTORE8, RETURN, REVERT 下一个状态对应pure_memory_gas
        let following_pure_memory_gas = selector.select(&[
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        ]);
        let next_is_pure_memory_gas = meta.query_advice(config.vers[NUM_VERS - 2], Rotation::cur());

        // log0, log1, log2, log3, log4 下一个状态对应log_gas
        let following_log_gas = selector.select(&[
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
            1.expr(),
        ]);
        let next_is_log_gas = meta.query_advice(config.vers[NUM_VERS - 3], Rotation::cur());

        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![
                    ExecutionState::CALLDATACOPY,
                    ExecutionState::CODECOPY,
                    ExecutionState::EXTCODECOPY,
                    ExecutionState::RETURNDATACOPY,
                    ExecutionState::MEMORY,
                    ExecutionState::MSTORE8,
                    ExecutionState::RETURN_REVERT,
                    ExecutionState::LOG_BYTES,
                ],
                NUM_ROW,
                vec![
                    (
                        ExecutionState::MEMORY_COPIER_GAS,
                        memory_copier_gas::NUM_ROW,
                        Some(next_is_memory_copier_gas),
                    ),
                    (
                        ExecutionState::PURE_MEMORY_GAS,
                        memory_copier_gas::NUM_ROW,
                        Some(next_is_pure_memory_gas),
                    ),
                    (
                        ExecutionState::LOG_GAS,
                        log_gas::NUM_ROW,
                        Some(next_is_log_gas),
                    ),
                ],
                Some(vec![
                    following_memory_copier_gas,
                    following_pure_memory_gas,
                    following_log_gas,
                ]),
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let next_word_size = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });
        let curr_memory_quad_cost = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 1, Rotation::prev())
        });
        let next_memory_quad_cost = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 2, Rotation::prev())
        });

        vec![
            ("post_call_memory_gas next_word_size".into(), next_word_size),
            (
                "post_call_memory_gas curr_memory_quad_cost".into(),
                curr_memory_quad_cost,
            ),
            (
                "post_call_memory_gas next_memory_quad_cost".into(),
                next_memory_quad_cost,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let tag_selector_index = match trace.op {
            OpcodeId::CALLDATACOPY => 0,
            OpcodeId::CODECOPY => 1,
            OpcodeId::RETURNDATACOPY => 2,
            OpcodeId::EXTCODECOPY => 3,
            OpcodeId::MLOAD => 4,
            OpcodeId::MSTORE => 5,
            OpcodeId::MSTORE8 => 6,
            OpcodeId::RETURN => 7,
            OpcodeId::REVERT => 8,
            OpcodeId::LOG0 => 9,
            OpcodeId::LOG1 => 10,
            OpcodeId::LOG2 => 11,
            OpcodeId::LOG3 => 12,
            OpcodeId::LOG4 => 13,
            _ => panic!("memory gas not supported opcode"),
        };

        let memory_size = U256::from(current_state.new_memory_size.unwrap());
        // 取值后重置，该值为上一步计算后的值，例如extcodecopy、callcodecopy等
        current_state.new_memory_size = None;
        // next_word_size = Max(cur_memory_size, memory_size)
        // res[0] == 1, curr_memory_word_size < res[1] = memory_size = memory_size + 31 / 32
        // res[0] == 0, curr_memory_word_size >= res[1]
        // SimpleLtGadget occupies 7 cells(lt + diff + arithmetic 5), and memory expansion only occupies 5 cells.
        let curr_memory_word_size = U256::from(current_state.memory_chunk_prev);
        let (next_word_size_row, res) =
            operation::memory_expansion::gen_witness(vec![memory_size, curr_memory_word_size]);
        let next_word_size = if res[0].is_zero() {
            curr_memory_word_size
        } else {
            res[1]
        };
        // cur_memory_word_size * cur_memory_word_size / 512 = curr_quad_memory_cost
        let (curr_memory_quad_cost_row, cur_memory_quad_gas_res) =
            operation::u64div::gen_witness(vec![
                (curr_memory_word_size * curr_memory_word_size).into(),
                U256::from(GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR),
            ]);

        // next_memory_word_size * next_memory_word_size / 512 = next_quad_memory_cost
        let (next_memory_quad_cost_row, next_memory_quad_gas_res) =
            operation::u64div::gen_witness(vec![
                (next_word_size * next_word_size).into(),
                U256::from(GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR),
            ]);

        // gas cost = MEMORY_EXPANSION_LINEAR_COEFF(3) * (next_memory_word_size.clone() - curr_memory_word_size) + (next_quad_memory_cost.quotient() - curr_quad_memory_cost.quotient())
        let gas_cost = U256::from(GasCost::MEMORY_EXPANSION_LINEAR_COEFF)
            * (next_word_size - U256::from(curr_memory_word_size))
            + (next_memory_quad_gas_res[0] - cur_memory_quad_gas_res[0]);
        current_state.memory_gas_cost = gas_cost.as_u64();

        // core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_arithmetic_tiny_lookup(0, &next_word_size_row);
        core_row_1.insert_arithmetic_tiny_lookup(1, &curr_memory_quad_cost_row);
        core_row_1.insert_arithmetic_tiny_lookup(2, &next_memory_quad_cost_row);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
                CORE_ROW_1_START_COL_IDX + 3,
                CORE_ROW_1_START_COL_IDX + 4,
                CORE_ROW_1_START_COL_IDX + 5,
                CORE_ROW_1_START_COL_IDX + 6,
                CORE_ROW_1_START_COL_IDX + 7,
                CORE_ROW_1_START_COL_IDX + 8,
                CORE_ROW_1_START_COL_IDX + 9,
                CORE_ROW_1_START_COL_IDX + 10,
                CORE_ROW_1_START_COL_IDX + 11,
                CORE_ROW_1_START_COL_IDX + 12,
                CORE_ROW_1_START_COL_IDX + 13,
            ],
            tag_selector_index as usize,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let mut core_row_0 = ExecutionState::MEMORY_GAS.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // 如果下一个状态为MEMORY_COPIER_GAS,设置NUM_VERS - 1为1
        match current_state.next_exec_state {
            Some(ExecutionState::MEMORY_COPIER_GAS) => {
                assign_or_panic!(core_row_0[NUM_VERS - 1], U256::one());
            }
            Some(ExecutionState::PURE_MEMORY_GAS) => {
                assign_or_panic!(core_row_0[NUM_VERS - 2], U256::one());
            }
            Some(ExecutionState::LOG_GAS) => {
                assign_or_panic!(core_row_0[NUM_VERS - 3], U256::one());
            }
            _ => (),
        }
        // 给后续的计算提前规划好位置
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            gas_cost
        );

        // 在外部gen_witness时，我们将current.gas_left预处理为trace.gas - trace.gas_cost
        // 但是某些复杂的gas计算里，真正的gas计算是在执行状态的最后一步，此时我们需要保证这里的gas_left与
        // 上一个状态的gas_left一致，也即trace.gas。
        // 在生成core_row_0时我们没有改变current.gas_left是因为这样做会导致重复的代码。
        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());

        let mut arithmetic = vec![];
        arithmetic.extend(next_word_size_row);
        arithmetic.extend(curr_memory_quad_cost_row);
        arithmetic.extend(next_memory_quad_cost_row);

        Witness {
            core: vec![core_row_1, core_row_0],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(MemoryGasGadget {
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
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let state_stamp_init = 3;
        current_state.state_stamp = state_stamp_init + 3 + 2 * 0x04 + 2 + 4;
        current_state.call_id_new = state_stamp_init + 1;
        current_state.new_memory_size = Some(0);
        current_state.next_exec_state = Some(ExecutionState::MEMORY_COPIER_GAS);
        let code_addr = U256::from_str_radix("0x1234", 16).unwrap();
        let mut bytecode = HashMap::new();
        // 32 byte
        let code = Bytecode::from(
            hex::decode("7c00000000000000000000000000000000000000000000000000000000005038")
                .unwrap(),
        );
        bytecode.insert(code_addr, code);
        current_state.bytecode = bytecode;

        let mut trace = prepare_trace_step!(0, OpcodeId::CALLDATACOPY, stack);
        trace.gas = 0x254023;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALLDATACOPY.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY] =
                Some(state_stamp_init.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(U256::from(0x254023));
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::MEMORY_COPIER_GAS.into_exec_state_core_row(
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
        prover.assert_satisfied_par();
    }
}
