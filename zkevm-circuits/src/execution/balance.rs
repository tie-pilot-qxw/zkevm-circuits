// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, state, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;
const PC_DELTA: u64 = 1;
const STACK_POINTER_DELTA: u64 = 0;
/// BALANCE overview:
/// pop a value from the top of the stack: address,
/// get the corresponding balance according to the address,
/// and push the balance to the top of the stack
///
/// BALANCE Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// WARM_R(12 columns) means is_warm_read lookup,
/// WARM_W(12 columns) means is_warm_write lookup
/// STATE1(8 columns) means state table lookup(pop)
/// STATE2(8 columns) means state table lookup(push)
/// ARITH(start at column index 17, occupy 5 columns) means arithmetic u64overflow lookup
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 2 | WARM_R | WARM_W |     |          |
/// | 1 | STATE1 | STATE2 |ARITH|          |
/// | 0 | DYNA_SELECTOR   | AUX |          |
/// +---+-------+-------+-------+----------+
pub struct BalanceGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for BalanceGadget<F>
{
    fn name(&self) -> &'static str {
        "BALANCE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BALANCE
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
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let mut constraints = vec![];
        // core single constraints
        let delta_core = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta_core));
        // stack constraints
        // i == 0 pop, read
        // i == 1 push, write
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
        // opcode constraint
        constraints.push(("opcode".into(), opcode - OpcodeId::BALANCE.as_u8().expr()));
        // storage lookup constraint
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
                i + 2,
                NUM_ROW,
                0.expr(),
                0.expr(),
                stack_operands[0][0].clone(),
                stack_operands[0][1].clone(),
                state::Tag::AddrInAccessListStorage,
                is_write,
            ))
        }
        let gas_cost = select::expr(
            is_warm,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );
        // gas_left not overflow
        let current_gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 3, Rotation::prev())
        );
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left_u64_overflow".into());
        // u64 overflow constraint
        constraints.extend(gas_left_not_overflow.get_constraints());
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (arithmetic::Tag::U64Overflow as u8).expr(),
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
        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));
        // todo more constraints
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let is_warm_read = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-2))
        });
        let is_warm_write = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-2))
        });
        let stack_pop_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_push_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let u64_overflow_rows = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 3, Rotation::prev())
        });
        vec![
            ("is_warm_read".into(), is_warm_read),
            ("is_warm_write".into(), is_warm_write),
            ("stack pop lookup".into(), stack_pop_0),
            ("stack push lookup".into(), stack_push_0),
            ("u64 overflow rows".into(), u64_overflow_rows),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::BALANCE);
        let (stack_pop_0, address) = current_state.get_pop_stack_row_value(trace);
        let stack_push_0 =
            current_state.get_push_stack_row(trace, current_state.stack_top.unwrap_or_default());

        // check address is warm for gas
        let (is_warm_read, is_warm) = current_state.get_addr_access_list_read_row(address);
        let is_warm_write = current_state.get_addr_access_list_write_row(address, true, is_warm);
        // core_row_2
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_storage_lookups([&is_warm_read, &is_warm_write]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);
        // insert gas overflow
        let (u64_overflow_rows, _) =
            operation::u64overflow::gen_witness::<F>(vec![current_state.gas_left.into()]);
        core_row_1.insert_arithmetic_tiny_lookup(3, &u64_overflow_rows);

        let core_row_0 = ExecutionState::BALANCE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_push_0, is_warm_read, is_warm_write],
            arithmetic: u64_overflow_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(BalanceGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {

    use crate::{
        constant::{GAS_LEFT_IDX, STACK_POINTER_IDX},
        execution::test::{
            generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
        },
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: Some(0xff.into()),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + 0xA28;
        let mut trace = prepare_trace_step!(0, OpcodeId::BALANCE, stack);

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
}
