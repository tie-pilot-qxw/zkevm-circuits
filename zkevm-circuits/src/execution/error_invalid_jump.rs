use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::bytecode::BytecodeElement;
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{select, Expr};

use crate::arithmetic_circuit::operation;
use crate::arithmetic_circuit::operation::get_lt_operations;
use crate::execution::{
    end_call_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::public::Tag::CodeSize;
use crate::witness::state::Row;
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

/// Overview
///   pop an element from the top of the stack as the target PC value to jump to，and the target PC must be JUMPDEST.
///   
/// Table Layout:
///    STATE: State lookup(stack_top0), src: Core circuit, target: State circuit table, 8 columns
///    BYTECODE: Bytecode lookup, make sure the target PC exists in Bytecode, src: Core circuit, target: Bytecode circuit table, 8 columns
/// +---+-------+-------+-------+------------+-------------+---------------------------+-----------------+------------+
/// |cnt| 8 col | 8 col | 8 col | 20         | 21          | 22                        | 23              |   8col     |
/// +---+-------+-------+-------+------------+-------------+---------------------------+-----------------+------------+
/// | 2 |       |       |       |  lt_hi     |  lt_lo      | lt_diff_hi                | lt_diff_lo      |   PUBLIC   |
/// | 1 | STATE |       |       |  JUMP_TAG  |  JUMPI_TAG  | code_diff_inv(JUMPDEST)   | condition_inv   |   BYTECODE |
/// | 0 | DYNA_SELECTOR   | AUX |            |             |                           |                 |            |
/// +---+-------+-------+-------+------------+-------------+---------------------------+-----------------+------------+

const NUM_ROW: usize = 3;
const LT_INDEX: usize = 18;
const DIFF_INDEX: usize = 19;
const DIFF_INV_INDEX: usize = 20;
const COND_INDEX: usize = 21;
const JUMP_INDEX: usize = 22;
const JUMPI_INDEX: usize = 23;

const JUMP_STAMP_OR_STACK: usize = 1;
const JUMPI_STAMP_OR_STACK: usize = 2;
pub struct ErrorInvalidJumpGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ErrorInvalidJumpGadget<F>
{
    fn name(&self) -> &'static str {
        "ERROR_INVALID_JUMP"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ERROR_INVALID_JUMP
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, end_call_1::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let mut constraints = Vec::new();

        // 1. 通用约束: 辅助列约束，opcode等
        let is_jump = meta.query_advice(config.vers[JUMP_INDEX], Rotation::prev());
        let is_jumpi = meta.query_advice(config.vers[JUMPI_INDEX], Rotation::prev());
        let selector = SimpleSelector::new(&[is_jump.clone(), is_jumpi.clone()]);
        // 1.1 opcode is JUMP or JUMPI
        constraints.push((
            "opcode is JUMP or JUMPI".into(),
            opcode
                - selector.select(&[
                    OpcodeId::JUMP.as_u8().expr(),
                    OpcodeId::JUMPI.as_u8().expr(),
                ]),
        ));
        // 1.2 辅助列约束
        // if jump, then is_jump = 1, item[0] * is_jump = 1
        // if jumpi, then is_jumpi = 1, item[1] * is_jumpi = 2
        let state_stamp_delta =
            selector.select(&[JUMP_STAMP_OR_STACK.expr(), JUMPI_STAMP_OR_STACK.expr()]);
        let stack_pointer_delta =
            selector.select(&[-JUMP_STAMP_OR_STACK.expr(), -JUMPI_STAMP_OR_STACK.expr()]);
        let gas_left = selector.select(&[
            -OpcodeId::JUMP.constant_gas_cost().expr(),
            -OpcodeId::JUMPI.constant_gas_cost().expr(),
        ]);
        let auxiliary_delta = AuxiliaryOutcome {
            gas_left: ExpressionOutcome::Delta(gas_left),
            state_stamp: ExpressionOutcome::Delta(state_stamp_delta.clone()),
            stack_pointer: ExpressionOutcome::Delta(stack_pointer_delta.clone()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta));

        // 2. 约束state_lookup
        // 0-next_pc_hi
        // 1-next_pc_lo
        // 2-cond_hi
        // 3-cond_lo
        let mut operands = Vec::new();
        for i in 0..2 {
            let state_entry = config.get_state_lookup(meta, i);
            if i == 0 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    0.expr(),
                    false,
                ));
            } else {
                constraints.append(&mut config.get_stack_constraints_with_selector(
                    meta,
                    state_entry.clone(),
                    i,
                    NUM_ROW,
                    -1.expr(),
                    false,
                    is_jumpi.clone(),
                ));
            }

            let (_, _, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, state_entry);
            operands.push(value_hi);
            operands.push(value_lo);
        }

        // 3. 判断next_pc是否合法
        let (tag, [next_pc_hi, next_pc_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));
        let next_pc_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "next_pc_u64_overflow".into());
        constraints.extend([
            (
                "tag is U64OVERFLOW".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            (
                "next_pc_lo in state == next_pc_lo in arithemetic".into(),
                operands[1].clone() - next_pc_lo.clone(),
            ),
            (
                "next_pc_hi in state == next_pc_hi in arithemetic".into(),
                operands[0].clone() - next_pc_hi,
            ),
        ]);
        // 3.1 获取next_pc与code_size之间的大小比较
        let (_, _, [_, _, _, code_size_lo]) =
            extract_lookup_expression!(public, config.get_public_lookup(meta, 0));

        let next_pc = select::expr(
            next_pc_not_overflow.expr(),
            next_pc_lo,
            code_size_lo.clone(),
        );
        let lt = meta.query_advice(config.vers[LT_INDEX], Rotation::prev());
        let diff = meta.query_advice(config.vers[DIFF_INDEX], Rotation::prev());
        let (tag, [_, _, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 1));
        let not_overflow = SimpleIsZero::new(&overflow, &overflow_inv, "diff not overflow".into());
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            ("diff not overflow".into(), 1.expr() - not_overflow.expr()),
        ]);

        let is_lt = SimpleLtGadget::<F, 8>::new(&next_pc, &code_size_lo, &lt, &diff);
        constraints.extend(is_lt.get_constraints());

        // 3.2 获取not_code信息及next_code信息
        let (lookup_addr, _, next_opcode, not_code, _, _, _, _) =
            extract_lookup_expression!(bytecode, config.get_bytecode_full_lookup(meta));

        // is_code_diff_zero = 0, next_opcode != JUMPDEST
        let code_diff = next_opcode - OpcodeId::JUMPDEST.as_u8().expr();
        let code_diff_inv = meta.query_advice(config.vers[DIFF_INV_INDEX], Rotation::prev());

        let is_code_diff_zero = SimpleIsZero::new(
            &code_diff,
            &code_diff_inv,
            String::from("next_code - JUMPDEST"),
        );
        constraints.extend(is_code_diff_zero.get_constraints());

        constraints.extend([
            (
                // 3.3 如果next_pc < code_size，next_opcode != JUMPDEST 或 not_code == 1
                "if next_pc < code_size, then next_opcode != JUMPDEST or not_code == 1".into(),
                lt.expr() * (1.expr() - not_code) * is_code_diff_zero.expr(),
            ),
            (
                // 3.4 bytecode lookup addr = code addr
                "bytecode lookup addr = code addr".into(),
                code_addr - lookup_addr,
            ),
        ]);

        // 4.如果opcode是JUMPI，则condition为true，即非0.
        let condition_inv = meta.query_advice(config.vers[COND_INDEX], Rotation::prev());
        let is_condition_zero = SimpleIsZero::new(
            &(operands[2].clone() + operands[3].clone()),
            &condition_inv,
            String::from("jumpi_condition"),
        );

        constraints.extend([(
            "if opcode == JUMPI, then condition is not zero".to_string(),
            // is_condition_zero == 1, means condition == 0;
            is_jumpi.clone() * is_condition_zero.expr(),
        )]);

        constraints.append(&mut config.get_next_single_purpose_constraints(
            meta,
            CoreSinglePurposeOutcome {
                ..Default::default()
            },
        ));

        // 下一个状态是END_CALL_1
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::END_CALL_1, end_call_1::NUM_ROW, None)],
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
        let bytecode_lookup = query_expression(meta, |meta| config.get_bytecode_full_lookup(meta));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        let u64overflow_lookup_0 =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        let u64overflow_lookup_1 =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 1));
        vec![
            ("error_invalid_jump_lookup_stack_0".into(), stack_lookup_0),
            ("error_invalid_jump_lookup_stack_1".into(), stack_lookup_1),
            ("error_invalid_jump_lookup_bytecode".into(), bytecode_lookup),
            ("error_invalid_jump_lookup_public".into(), public_lookup),
            (
                "error_invalid_jump_lookup_u64overflow_0".into(),
                u64overflow_lookup_0,
            ),
            (
                "error_invalid_jump_lookup_u64overflow_1".into(),
                u64overflow_lookup_1,
            ),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // error 之后应该返回失败的标志
        current_state.return_success = false;

        let (stack_pop_0, next_pc) = current_state.get_pop_stack_row_value(&trace);
        let mut state = vec![stack_pop_0.clone()];

        let (stack_pop_1, condition) = if trace.op == OpcodeId::JUMPI {
            let (stack_pop, condition) = current_state.get_pop_stack_row_value(&trace);
            state.push(stack_pop.clone());
            (stack_pop, condition)
        } else {
            (
                Row {
                    ..Default::default()
                },
                0.into(),
            )
        };

        let bytecode = current_state
            .bytecode
            .get(&current_state.code_addr)
            .unwrap();
        let code_size = bytecode.code.len() as u64;

        // 1. 判断next_pc是否小于code_size
        let (u64overflow_row_1, result) = operation::u64overflow::gen_witness::<F>(vec![next_pc]);
        // 1.1 not u64overflow时，设置next_pc = code_size
        let next_pc = if result[0].is_zero() {
            next_pc.as_u64()
        } else {
            code_size
        };

        // 1.2 使用lt比较next_pc与code size大小
        // 这里已经能够确保我们的next_pc一定是u64了
        let (lt, diff, ..) = get_lt_operations(
            &next_pc.into(),
            &U256::from(code_size),
            &U256::from(2).pow(U256::from(64)),
        );
        // 1.3 diff的u64约束，保证正确性
        let (u64overflow_row_2, _) = operation::u64overflow::gen_witness::<F>(vec![diff]);

        // 2.构造bytecode lookup相关的数据
        // 主要逻辑为当next_pc合法时，预期为能够在bytecode table中找到该code，并且is_code == false或code != JUMPDEST
        // next_pc不合法时，预期为构造一个padding行
        let default_code = BytecodeElement {
            value: 0,
            // 注: padding行is_code填的是0，所以这里设置为了true
            is_code: true,
        };
        let code = bytecode.code.get(next_pc as usize).unwrap_or(&default_code);

        let opcode_id = OpcodeId::from(code.value);
        let is_code = code.is_code;
        let pc = if lt { next_pc } else { code_size };
        // 如果是push之类的操作，应该等于value
        let value = if is_code { 0 } else { code.value };

        // 2.1 判断next_code opcode_id是否为JUMPDEST
        let code_diff = F::from_u128(opcode_id.as_u8().into())
            - F::from_u128(OpcodeId::JUMPDEST.as_u8().into());
        let code_diff_inv =
            U256::from_little_endian(code_diff.invert().unwrap_or(F::ZERO).to_repr().as_ref());

        // 3. 如果为JUMPI出现的error，则condition一定不为0
        let condition_hi = F::from_u128((condition >> 128).as_u128());
        let condition_lo = F::from_u128(condition.low_u128());
        let condition_inv = U256::from_little_endian(
            (condition_hi + condition_lo)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );

        // 4. 构造core_row_2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        //  get public row and insert public row lookup
        let public_row = current_state.get_public_code_info_row(CodeSize, current_state.code_addr);
        core_row_2.insert_public_lookup(0, &public_row);
        core_row_2.insert_arithmetic_tiny_lookup(0, &u64overflow_row_1);
        core_row_2.insert_arithmetic_tiny_lookup(1, &u64overflow_row_2);

        // 5. 构造core_row_1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1]);
        core_row_1.insert_bytecode_full_lookup(
            pc,
            opcode_id,
            current_state.code_addr,
            Some(value.into()),
            !is_code,
        );

        assign_or_panic!(core_row_1[LT_INDEX], U256::from(lt as u8));
        assign_or_panic!(core_row_1[DIFF_INDEX], diff);

        let tag = match trace.op {
            OpcodeId::JUMP => 0,
            OpcodeId::JUMPI => 1,
            _ => panic!("Error invalid jump, expect opcode is JUMP or JUMPI"),
        };
        simple_selector_assign(
            &mut core_row_1,
            [JUMP_INDEX, JUMPI_INDEX],
            tag,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        assign_or_panic!(core_row_1[DIFF_INV_INDEX], code_diff_inv);
        assign_or_panic!(core_row_1[COND_INDEX], condition_inv);

        let core_row_0 = ExecutionState::ERROR_INVALID_JUMP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut arithmetic = u64overflow_row_1;
        arithmetic.extend(u64overflow_row_2);

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state,
            public: vec![public_row],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ErrorInvalidJumpGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::constant::GAS_LEFT_IDX;
    use eth_types::Bytecode;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_error_trace_step,
        prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, code_addr: U256, bytecode: HashMap<U256, Bytecode>, is_jump: bool) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            code_addr,
            bytecode,
            stack_pointer: stack.0.len(),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };

        let gas_left_before_exec = if is_jump {
            current_state.gas_left + OpcodeId::JUMP.constant_gas_cost()
        } else {
            current_state.gas_left + OpcodeId::JUMPI.constant_gas_cost()
        };

        let mut trace =
            prepare_error_trace_step!(0, OpcodeId::JUMP, stack, Some(String::from("Invalid Jump")));
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
    fn test_invalid_jump() {
        // PUSH1(4)
        // JUMP
        // PUSH1(1)
        // STOP
        let stack = Stack::from_slice(&[4.into()]);
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let mut bytecode = HashMap::new();
        // 32 byte
        let code = Bytecode::from(hex::decode("600456600100").unwrap());
        bytecode.insert(code_addr, code);
        run(stack, code_addr, bytecode, true);
    }
}
