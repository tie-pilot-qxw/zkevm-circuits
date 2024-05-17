use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::{GasCost, OpcodeId, MAX_EXPANDED_MEMORY_ADDRESS};
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{select, Expr};

use crate::arithmetic_circuit::operation;
use crate::constant::{
    ARITHMETIC_TINY_COLUMN_WIDTH, ARITHMETIC_TINY_START_IDX, GAS_LEFT_IDX, NUM_AUXILIARY,
};
use crate::execution::storage::get_multi_inverse;
use crate::execution::ExecutionState::CALL_5;
use crate::execution::{
    call_5, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::{MemoryExpansion, U64Div};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: usize = 4;
const STACK_POINTER_DELTA: i32 = 0;

/// call_4 前一个指令为call_3, 后一个指令为call_5， call_4用于计算call的memory gas cost
/// call_4 需要4个栈元素：
/// - args_offset, args_length, ret_offset, ret_length: 计算读取的数据位置
///
/// Table layout:
///     cnt = 1, STATE0, STATE1, STATE2, STATE3 represent args_offset, args_length, ret_offset, ret_length respectively.
///     cnt = 2:
///         1. U64Div is `(args_offset + args_length + 31) / 32`;
///         2. MemoryExpansion is `Max((ret_offset + ret_length + 31) / 32, args_word_size)`;
///         3. MemoryExpansion is `Max(cur_memory_word_size * 32, max_word_size)`;
///         4. U64Div is `cur_memory_word_size * cur_memory_word_size / 512 = curr_quad_memory_cost`;
///         5. U64Div is `next_memory_word_size * next_memory_word_size / 512 = next_quad_memory_cost`;
///         5. args_len_inv, ret_len_inv is `args_length, ret_length is zero` needed parameters;
///
/// +-----+----------------+-------------------------+-------------------------+----------------+---------------------+------------------+-----------------+
/// | cnt |                |                         |                         |                |                     |                  |                 |
/// +-----+----------------+-------------------------+-------------------------+----------------+---------------------+------------------+-----------------+
/// | 2   | U64Div(2..6)   | MemoryExpansion(7..11)  | MemoryExpansion(12..16) | U64Div(17..21) | U64Div(22..26)      | args_len_inv(27) | ret_len_inv(28) |
/// | 1   | STATE0(0..7)   | STATE1(8..15)           | STATE2(16..23)          | STATE3(24..31) |                     |                  |                 |
/// | 0   | DYNAMIC(0..17) | AUX(18..24)             | STATE_STAMP_INIT(25)    | MEMORY_GAS(26) |                     |                  |                 |
/// +-----+----------------+-------------------------+-------------------------+----------------+---------------------+------------------+-----------------+

pub struct Call4Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call4Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_4"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_4
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, call_5::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let mut constraints = vec![];
        // stack constraints
        let mut operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                -3.expr() - i.expr(),
                false,
            ));

            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi.clone(), value_lo.clone()]);
            // args_offset, args_length, ret_offset, ret_length is u64, high 128 bits is zero
            // evm if offset or length overflow, return ErrGasUintOverflow
            constraints.push((
                "memory gas value_hi in stack is zero".into(),
                value_hi.clone(),
            ));
        }

        // args_word_size = (args_offset + args_length + 31) / 32
        // input: [args_size + 31, 32]
        let (args_word_tag, [args_size, denominator, args_word_size_result, _]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 0));

        // Max(ret_word_size, args_word_size) = max_word_size
        // input: [ret_offset + ret_length, args_word_size]
        let (max_word_tag, [ret_size, args_word_size, lt_1, ret_word_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 1));

        let max_word_size =
            select::expr(lt_1.clone(), ret_word_size.clone(), args_word_size.clone());

        // Max(cur_memory_word_size, max_word_size) = next_word_size
        // input: [cur_memory_size * 32, max_word_size]
        let memory_chunk_prev = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 2],
            Rotation(-1 * NUM_ROW as i32),
        );

        let (next_word_tag, [curr_mem_size, max_word_size_input, lt_2, curr_mem_word_size]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 2));

        let next_word_size = select::expr(
            lt_2.clone(),
            curr_mem_word_size.clone(),
            max_word_size_input.clone(),
        );

        // cur_memory_word_size * cur_memory_word_size / 512 = curr_quad_memory_cost
        let (
            curr_quad_memory_cost_tag,
            [cur_memory_size_numerator, cur_memory_size_denominator, curr_quad_memory_cost, _],
        ) = extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 3));

        // next_memory_size * next_memory_size / 512 = next_quad_memory_cost
        let (
            next_quad_memory_cost_tag,
            [next_memory_size_numerator, next_memory_size_denominator, next_quad_memory_cost, _],
        ) = extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 4));

        let args_len_inv = meta.query_advice(
            config.vers[5 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX],
            Rotation(-2),
        );
        let ret_len_inv = meta.query_advice(
            config.vers[5 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 1],
            Rotation(-2),
        );

        let args_len_is_zero = SimpleIsZero::new(
            &(operands[1][0].clone() + operands[1][1].clone()),
            &args_len_inv,
            "args_length is zero".into(),
        );
        constraints.extend(args_len_is_zero.get_constraints());
        let ret_len_is_zero = SimpleIsZero::new(
            &(operands[3][0].clone() + operands[3][1].clone()),
            &ret_len_inv,
            "ret_length is zero".into(),
        );
        constraints.extend(ret_len_is_zero.get_constraints());

        // real args_size
        let args_size_input = args_len_is_zero.expr() * 0.expr()
            + (1.expr() - args_len_is_zero.expr())
                * (operands[0][1].clone() + operands[1][1].clone());
        let ret_size_input = ret_len_is_zero.expr() * 0.expr()
            + (1.expr() - ret_len_is_zero.expr())
                * (operands[2][1].clone() + operands[3][1].clone());

        // stack, arithmetic input, tag constraints
        constraints.extend([
            // args_word_size = (args_size + 31) / 32
            // tag: U64DIV
            // input: [args_size + 31, 32]
            // output: [args_word_size_result]
            (
                "args_word_tag is U64DIV".into(),
                args_word_tag - (U64Div as u8).expr(),
            ),
            (
                "args_size_input + 31 == args_size".into(),
                args_size_input + 31.expr() - args_size.clone(),
            ),
            ("denominator is 32".into(), denominator - 32.expr()),
            // Max(ret_word_size, args_word_size) = max_word_size
            // tag: MemoryExpansion
            // input: [ret_size, args_word_size] -> prev step args_word_size == args_word_size
            // output: lt (bool), ret_word_size
            // note, ret_word_size use lookup constraints
            (
                "max_word_tag is MemoryExpansion".to_string(),
                max_word_tag - (MemoryExpansion as u8).expr(),
            ),
            (
                "ret_size_input == ret_size".into(),
                ret_size_input - ret_size.clone(),
            ),
            (
                "args_word_size_result == args_word_size".into(),
                args_word_size_result - args_word_size,
            ),
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
                "curr_mem_size == memory_chunk * 32".into(),
                curr_mem_size - memory_chunk_prev.clone() * 32.expr(),
            ),
            (
                "max_word_size_input == max_word_size".into(),
                max_word_size_input - max_word_size,
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
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            Rotation::cur(),
        );
        constraints.push(("gas cost".to_string(), gas_cost - memory_gas_cost));

        // core constraints
        let state_stamp_init = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation(-1 * NUM_ROW as i32),
        );
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        // append constraint for the next execution state's stamp_init
        constraints.extend([(
            "state_init_for_next_gadget correct".into(),
            stamp_init_for_next_gadget - state_stamp_init,
        )]);

        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(0.expr()), // 此处的gas_left值与CALL1-3保持一致
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta.clone()));
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, delta));

        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
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
        // prev state is CALL_3
        // next state is POST_CALL
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![ExecutionState::CALL_3],
                NUM_ROW,
                vec![(CALL_5, call_5::NUM_ROW, None)],
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
        let stack_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        let args_div = query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 0));
        let max_word_size =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 1));
        let next_word_size =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 2));
        let curr_memory_quad_cost =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 3));
        let next_memory_quad_cost =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 4));

        vec![
            ("call_4 stack read args_offset".into(), stack_lookup_0),
            ("call_4 stack read args_length".into(), stack_lookup_1),
            ("call_4 stack read ret_offset".into(), stack_lookup_2),
            ("call_4 stack read ret_length".into(), stack_lookup_3),
            ("call_4 args_div".into(), args_div),
            ("call_4 max_word_size".into(), max_word_size),
            ("call_4 next_word_size".into(), next_word_size),
            ("call_4 curr_memory_quad_cost".into(), curr_memory_quad_cost),
            ("call_4 next_memory_quad_cost".into(), next_memory_quad_cost),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_read_0, args_offset) = current_state.get_peek_stack_row_value(trace, 4);
        let (stack_read_1, args_length) = current_state.get_peek_stack_row_value(trace, 5);
        let (stack_read_2, ret_offset) = current_state.get_peek_stack_row_value(trace, 6);
        let (stack_read_3, ret_length) = current_state.get_peek_stack_row_value(trace, 7);

        let (args_len_inv) = get_multi_inverse::<F>(args_length);
        let (ret_len_inv) = get_multi_inverse::<F>(ret_length);

        let args_size = if args_length.is_zero() {
            U256::zero()
        } else {
            args_offset + args_length
        };
        assert!(args_size <= U256::from(MAX_EXPANDED_MEMORY_ADDRESS));
        let ret_size = if ret_length.is_zero() {
            U256::zero()
        } else {
            ret_offset + ret_length
        };
        assert!(args_size <= U256::from(MAX_EXPANDED_MEMORY_ADDRESS));

        // args_word_size = (args_offset + args_length + 31) / 32
        let (args_div_row, args_res) =
            operation::u64div::gen_witness(vec![args_size + 31, U256::from(32)]);
        // max_word_size = Max(ret_offset + ret_length, args_word_size)
        // res[0] == 1, args_res[0] < res[1] = ret_word_size = (ret_size + 31) / 32
        // res[0] == 0, args_res[0] >= res[1] = ret_word_size = (ret_size + 31) / 32
        let (max_word_size_row, res) =
            operation::memory_expansion::gen_witness(vec![ret_size, args_res[0]]);
        let max_word_size = if res[0].is_zero() {
            args_res[0]
        } else {
            res[1]
        };
        // next_word_size = Max(cur_memory_size, max_word_size)
        // curr_memory_word_size is the state before executing the opcode, so we use current_state.memory_chunk_prev.
        // res[0] == 1, max_word_size < res[1] = cur_memory_word_size = current_state.memory_chunk_prev + 31 / 32;
        // res[0] == 0, max_word_size >= res[1];
        // SimpleLtGadget occupies 7 cells(lt + diff + arithmetic 5), and memory expansion only occupies 5 cells.
        let curr_memory_word_size = U256::from(current_state.memory_chunk_prev);
        let (next_word_size_row, res) = operation::memory_expansion::gen_witness(vec![
            curr_memory_word_size * 32,
            max_word_size,
        ]);
        let next_word_size = if res[0].is_zero() {
            max_word_size
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
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        core_row_2.insert_arithmetic_tiny_lookup(0, &args_div_row);
        core_row_2.insert_arithmetic_tiny_lookup(1, &max_word_size_row);
        core_row_2.insert_arithmetic_tiny_lookup(2, &next_word_size_row);
        core_row_2.insert_arithmetic_tiny_lookup(3, &curr_memory_quad_cost_row);
        core_row_2.insert_arithmetic_tiny_lookup(4, &next_memory_quad_cost_row);

        assign_or_panic!(
            core_row_2[5 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX],
            args_len_inv
        );
        assign_or_panic!(
            core_row_2[5 * ARITHMETIC_TINY_COLUMN_WIDTH + ARITHMETIC_TINY_START_IDX + 1],
            ret_len_inv
        );

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([
            &stack_read_0,
            &stack_read_1,
            &stack_read_2,
            &stack_read_3,
        ]);

        let mut core_row_0 = ExecutionState::CALL_4.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let stamp_init = current_state.call_id_new - 1;
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            stamp_init.into()
        );
        // 给后续的计算提前规划好位置
        assign_or_panic!(
            core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY + 1],
            gas_cost
        );

        // CALL1到CALL4时还未进行gas计算，此时gas_left为trace.gas
        core_row_0[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] = Some(trace.gas.into());

        let mut arithmetic = vec![];
        arithmetic.extend(args_div_row);
        arithmetic.extend(max_word_size_row);
        arithmetic.extend(next_word_size_row);
        arithmetic.extend(curr_memory_quad_cost_row);
        arithmetic.extend(next_memory_quad_cost_row);

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_read_0, stack_read_1, stack_read_2, stack_read_3],
            arithmetic,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call4Gadget {
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

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::CALL_3.into_exec_state_core_row(
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
            let row = ExecutionState::CALL_5.into_exec_state_core_row(
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
