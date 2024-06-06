use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;

use crate::arithmetic_circuit::operation;
use crate::constant::{GAS_LEFT_IDX, NEW_MEMORY_SIZE_OR_GAS_COST_IDX, NUM_AUXILIARY, NUM_VERS};
use crate::execution::ExecutionState::END_CALL;
use crate::execution::{
    end_call, memory_gas, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome,
    ExecStateTransition, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

const PC_DELTA: usize = 1;
pub(super) const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: usize = 0;

const CORE_ROW_1_START_COL_IDX: usize = 7;

/// pure_memory_gas 前一个指令为memory_gas
/// 对应的opcode: MLOAD, MSTORE, MSTORE8, RETURN, REVERT
///
/// Table layout:
///     cnt = 1:
///         1. U64OVERFLOW is `gas_left u64 constraints`.
///         2. SELECTOR is opcode selector.
///
/// +-----+--------------+--------------+-----------------------+
/// | cnt |              |              |                       |
/// +-----+--------------+--------------+-----------------------+
/// | 1   | U64OVERFLOW  | SELECTOR(7..11)  |                   |
/// | 0   | DYNAMIC(0..17) | AUX(18..24)|                       |
/// +-----+--------------+--------------+-----------------------+

pub struct PureMemoryGasGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PureMemoryGasGadget<F>
{
    fn name(&self) -> &'static str {
        "PURE_MEMORY_GAS"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::PURE_MEMORY_GAS
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW + memory_gas::NUM_ROW, end_call::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];

        // current gas left is u64
        let Auxiliary { gas_left, .. } = config.get_auxiliary();
        let current_gas_left = meta.query_advice(gas_left, Rotation::cur());

        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        );
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left_u64_overflow".into());
        constraints.extend(gas_left_not_overflow.get_constraints());

        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
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

        // core constraints
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let selector = SimpleSelector::new(&[
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 3], Rotation::prev()),
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 4], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());
        constraints.push((
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::MLOAD.as_u8().expr(),
                opcode.clone() - OpcodeId::MSTORE.as_u8().expr(),
                opcode.clone() - OpcodeId::MSTORE8.as_u8().expr(),
                opcode.clone() - OpcodeId::RETURN.as_u8().expr(),
                opcode.clone() - OpcodeId::REVERT.as_u8().expr(),
            ]),
        ));

        // return data size constraints
        let return_data_size_for_next = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        let return_data_size_prev = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32 - 1 * memory_gas::NUM_ROW as i32),
        );
        let is_return_or_revert =
            selector.select(&[0.expr(), 0.expr(), 0.expr(), 1.expr(), 1.expr()]);
        constraints.push((
            "return or revert opcode => return data size is correct".into(),
            is_return_or_revert.clone() * (return_data_size_for_next - return_data_size_prev),
        ));

        let constant_gas = selector.select(&[
            OpcodeId::MLOAD.constant_gas_cost().expr(),
            OpcodeId::MSTORE.constant_gas_cost().expr(),
            OpcodeId::MSTORE8.constant_gas_cost().expr(),
            OpcodeId::RETURN.constant_gas_cost().expr(),
            OpcodeId::REVERT.constant_gas_cost().expr(),
        ]);
        let memory_gas_cost = meta.query_advice(
            config.vers[NUM_STATE_HI_COL
                + NUM_STATE_LO_COL
                + NUM_AUXILIARY
                + NEW_MEMORY_SIZE_OR_GAS_COST_IDX],
            Rotation(-1 * NUM_ROW as i32),
        );
        let gas_cost = memory_gas_cost + constant_gas;

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        let prev_core_single_delta = CoreSinglePurposeOutcome::default();
        constraints.append(&mut config.get_cur_single_purpose_constraints(
            meta,
            NUM_ROW,
            prev_core_single_delta,
        ));
        // append core single purpose constraints
        // return revert PC不会增加1
        let next_pc = selector.select(&[
            PC_DELTA.expr(),
            PC_DELTA.expr(),
            PC_DELTA.expr(),
            0.expr(),
            0.expr(),
        ]);

        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            // 因为pc向后移动1，该指令下同一笔交易中其它状态不变
            pc: ExpressionOutcome::Delta(next_pc),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // return, revert 下一个状态是END_CALL
        let next_is_end_call = meta.query_advice(config.vers[NUM_VERS - 1], Rotation::cur());
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::MEMORY_GAS],
                NUM_ROW,
                vec![(END_CALL, end_call::NUM_ROW, Some(next_is_end_call))],
                Some(vec![is_return_or_revert]),
            ),
        ));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let overflow = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });

        vec![("pure_memory_gas gas overflow".into(), overflow)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let tag_selector_index = match trace.op {
            OpcodeId::MLOAD => 0,
            OpcodeId::MSTORE => 1,
            OpcodeId::MSTORE8 => 2,
            OpcodeId::RETURN => 3,
            OpcodeId::REVERT => 4,
            _ => panic!("pure memory gas not supported opcode"),
        };

        let (overflow_rows, _) =
            operation::u64overflow::gen_witness::<F>(vec![U256::from(current_state.gas_left)]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_arithmetic_tiny_lookup(0, &overflow_rows);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
                CORE_ROW_1_START_COL_IDX + 3,
                CORE_ROW_1_START_COL_IDX + 4,
            ],
            tag_selector_index as usize,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let mut core_row_0 = ExecutionState::PURE_MEMORY_GAS.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // return, revert 固定预留的位置
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            current_state.returndata_size
        );

        // 如果下一个状态为END_CALL,设置NUM_VERS - 1为1
        match current_state.next_exec_state {
            Some(ExecutionState::END_CALL) => {
                assign_or_panic!(core_row_0[NUM_VERS - 1], U256::one());
            }
            _ => (),
        }

        let mut arithmetic = vec![];
        arithmetic.extend(overflow_rows);

        Witness {
            core: vec![core_row_1, core_row_0],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(PureMemoryGasGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 32];
        let value = U256::from_big_endian(&value_vec);

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(value),
            memory_chunk_prev: ((0xffff + 31) / 32) + 1,
            memory_chunk: ((0xffff + 31) / 32) + 1,
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };

        let new_memory_size = (stack.last().unwrap() + 31) / 32;
        let mut gas_cost = OpcodeId::MLOAD.constant_gas_cost();
        if new_memory_size.as_u64() > current_state.memory_chunk {
            gas_cost = gas_cost
                + GasCost::MEMORY_EXPANSION_LINEAR_COEFF
                    * (new_memory_size.as_u64() - current_state.memory_chunk_prev)
                + (new_memory_size.as_u64() * new_memory_size.as_u64()
                    / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR
                    - current_state.memory_chunk_prev * current_state.memory_chunk_prev
                        / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR);
        }
        let gas_left_before_exec = current_state.gas_left + gas_cost;

        let mut trace = prepare_trace_step!(0, OpcodeId::MLOAD, stack);
        trace.gas = gas_left_before_exec;

        trace.memory.0 = vec![0; 0x1001f];
        for i in 0..32 {
            trace.memory.0.insert(0xffff + i, value_vec[i]);
        }

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::MEMORY_GAS.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
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
}
