// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::constant::{END_TX_NEXT_IS_BEGIN_TX1, END_TX_NEXT_IS_END_BLOCK, NUM_AUXILIARY};
use crate::execution::{begin_tx_1, end_block, ExecStateTransition};
use crate::execution::{AuxiliaryOutcome, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(crate) const NUM_ROW: usize = 3;
const TX_DIFF_COL_IDX: usize = 23;
pub struct EndTxGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for EndTxGadget<F>
{
    fn name(&self) -> &'static str {
        "END_TX"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::END_TX
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, begin_tx_1::NUM_ROW)
    }

    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        // 约束辅助列的所有元素与上一个指令相同
        let delta = AuxiliaryOutcome {
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // END_TX不需要做single_purpose_constraints
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());

        let tx_num_entry = config.get_public_lookup(meta, 0);
        let (_, _, [public_tx_num_in_block, _, _, _]) =
            extract_lookup_expression!(public, tx_num_entry.clone());

        // constraint tx_id_diff and tx_idx_diff_inv
        let tx_idx_diff_inv = meta.query_advice(config.vers[TX_DIFF_COL_IDX], Rotation(-2));
        let is_zero = SimpleIsZero::new(
            &(public_tx_num_in_block.clone() - tx_idx.clone()),
            &tx_idx_diff_inv,
            String::from("tx_id_diff"),
        );
        constraints.append(&mut is_zero.get_constraints());

        let block_idx = meta.query_advice(config.block_idx, Rotation::cur());

        // constraint tag and block_idx in public entry
        constraints.extend(config.get_public_constraints(
            meta,
            tx_num_entry,
            (public::Tag::BlockTxLogNumAndPrevrandao as u8).expr(),
            Some(block_idx.clone()),
            [None, None, None, None],
        ));

        let next_is_end_block = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + END_TX_NEXT_IS_END_BLOCK],
            Rotation::cur(),
        );
        let next_is_begin_tx1 = meta.query_advice(
            config.vers
                [NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + END_TX_NEXT_IS_BEGIN_TX1],
            Rotation::cur(),
        );
        // 约束下一个执行状态
        constraints.append(&mut config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::END_CALL_2],
                NUM_ROW,
                vec![
                    // 非区块中最后一笔交易时（即tx_id_diff>0），约束下一个状态为begin_tx_1
                    // BEGIN_TX_1 ==》 is_zero=0;
                    (
                        ExecutionState::BEGIN_TX_1,
                        begin_tx_1::NUM_ROW,
                        Some(next_is_begin_tx1),
                    ),
                    // 区块中最后一笔交易时（即tx_id_diff=0），约束下一个状态为end_block
                    // END_BLOCK ==》is_zero=1
                    (
                        ExecutionState::END_BLOCK,
                        end_block::NUM_ROW,
                        Some(next_is_end_block),
                    ),
                ],
                // cond_expr字段的值计算后要等于1，因为get_exec_state_constraints
                // 内对所有变量计算后的整体表达式-1来保证约束成立
                Some(vec![1.expr() - is_zero.expr(), is_zero.expr()]),
            ),
        ));
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let public_entry = query_expression(meta, |meta| config.get_public_lookup(meta, 0));

        vec![("public entry".into(), public_entry)]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        let core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        let mut core_row_0 = ExecutionState::END_TX.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // 计算当前交易是否为最后一笔交易，如果tx_num_diff为0，则表示为当前区块的最后一笔交易
        // 使用SimpleGadget电路，需要两数的差值以及其对应的相反数
        let tx_num_diff = (&current_state
            .tx_num_in_block
            .get(&current_state.block_idx)
            .unwrap()
            .to_owned()
            - current_state.tx_idx) as u64;

        let tx_num_diff_inv = U256::from_little_endian(
            F::from(tx_num_diff)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        // 将差值的相反数填入core_row_2的23列
        assign_or_panic!(core_row_2[TX_DIFF_COL_IDX], tx_num_diff_inv);

        // core_row_2添加public entry记录总的交易数，
        core_row_2.insert_public_lookup(
            0,
            &current_state.get_public_tx_row(public::Tag::BlockTxLogNumAndPrevrandao, 0),
        );

        // 根据next exec state 填充core row0 的 下一个状态是begin_tx_1(列25) 还是 end_block(列26),分别在对应的列置为1
        match current_state.next_exec_state {
            Some(ExecutionState::BEGIN_TX_1) => {
                assign_or_panic!(
                    core_row_0[NUM_STATE_HI_COL
                        + NUM_STATE_LO_COL
                        + NUM_AUXILIARY
                        + END_TX_NEXT_IS_BEGIN_TX1],
                    U256::one()
                );
            }
            Some(ExecutionState::END_BLOCK) => {
                assign_or_panic!(
                    core_row_0[NUM_STATE_HI_COL
                        + NUM_STATE_LO_COL
                        + NUM_AUXILIARY
                        + END_TX_NEXT_IS_END_BLOCK],
                    U256::one()
                );
            }
            _ => (),
        }
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(EndTxGadget {
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

    fn assign_and_constraint(next_state: ExecutionState, tx_idx: usize, tx_num_in_block: usize) {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_top: None,
            tx_idx,
            block_idx: 1,
            ..WitnessExecHelper::new()
        };
        current_state.tx_num_in_block.insert(1, tx_num_in_block);
        current_state.log_num_in_block.insert(1, 0);

        let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = next_state.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        current_state.next_exec_state = Some(next_state);
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_next_state_end_block() {
        assign_and_constraint(ExecutionState::END_BLOCK, 8, 8);
    }

    #[test]
    fn test_next_state_begin_tx1() {
        assign_and_constraint(ExecutionState::BEGIN_TX_1, 6, 8);
    }
}
