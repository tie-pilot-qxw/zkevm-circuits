use crate::arithmetic_circuit::operation::u64overflow;

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{arithmetic, copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
/// The number of bytes in one calldataload operation
const LOAD_SIZE: usize = 32;
const STATE_STAMP_DELTA: usize = 34;
const PC_DELTA: usize = 1;
const STACK_POINTER_DELTA: usize = 0;

pub struct CalldataloadGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Calldataload read word from msg data at index idx in EVM,
/// idx in stack and will retrieve data from msg.data[idx:idx+32] to stack.
/// data[idx]: 32-byte value starting from the given offset of the calldata.
/// All bytes after the end of the calldata are set to 0.
///
/// Calldataload Execution State layout is as follows
/// where STATE means state table lookup,
/// arith0 means whether offset of calldata is u64overflow,
/// copy0/1 means the bytes retried from msg.data (calldata),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col  |
/// +---+-------+-------+-------+----------+
/// | 2 | copy0  | copy1  | arith0 |       |
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CalldataloadGadget<F>
{
    fn name(&self) -> &'static str {
        "CALLDATALOAD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALLDATALOAD
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-OpcodeId::CALLDATALOAD.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        let delta_core = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta_core));

        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        let mut operands = vec![];
        // 因为32byte拆分为2组16byte记录在state中
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i * (LOAD_SIZE + 1), // pop index and load 32 byte from calldata; so index = 1+load_size
                NUM_ROW,
                STACK_POINTER_DELTA.expr(),
                i == 1,
            ));
            // 1 state entry: pop index of calldata from stack;
            // value_hi=index[..16]; value_lo=index[16..]
            // 2 state entry: push value which is retrived from calldata
            // value_hi=data[..16] value_lo=data[16..]
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let (tag, [value_hi, value_lo, overflow, overflow_inv]) =
            extract_lookup_expression!(arithmetic_tiny, config.get_arithmetic_tiny_lookup(meta, 4));
        let not_overflow = SimpleIsZero::new(&overflow, &overflow_inv, "u64 overflow".into());
        for i in 0..2 {
            let copy_entry = if i == 0 {
                config.get_copy_lookup(meta, 0)
            } else {
                config.get_copy_lookup(meta, 1)
            };
            let (_, stamp, ..) =
                extract_lookup_expression!(state, config.get_state_lookup(meta, 0));
            constraints.append(&mut config.get_copy_constraints(
                copy::Tag::Calldata,
                call_id.clone(),
                // not_overflow index of calldata = value_lo + 16*i;
                // overflow index of calldata = u64::max+16*i
                (not_overflow.expr() * operands[0][1].clone()
                    + (1.expr() - not_overflow.expr()) * (u64::MAX - 32).expr())
                    + (16 * i).expr(),
                // +1 ==> because pop index; copy的32byte数据分为2部分，所以16*i;
                stamp.clone() + (1 + 16 * i).expr(),
                copy::Tag::Null,
                0.expr(),
                0.expr(),
                0.expr(),
                Some(15.expr()),
                16.expr(),
                0.expr(),
                Some(operands[1][i].clone()), // data of copy from calldata
                copy_entry.clone(),
            ));
        }

        constraints.extend([
            (
                "CALLDATALOAD opcode".into(),
                opcode - OpcodeId::CALLDATALOAD.as_u8().expr(),
            ),
            (
                "value_hi=operands[0][0]".into(),
                value_hi - operands[0][0].clone(),
            ),
            (
                "value_lo=operands[0][1]".into(),
                value_lo - operands[0][1].clone(),
            ),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::U64Overflow as u8).expr(),
            ),
        ]);
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_pop = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_push = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let copy_lookup_0 = query_expression(meta, |meta| config.get_copy_lookup(meta, 0));
        let copy_lookup_1 = query_expression(meta, |meta| config.get_copy_lookup(meta, 1));
        let arithmetic_u64 =
            query_expression(meta, |meta| config.get_arithmetic_tiny_lookup(meta, 4));

        vec![
            ("stack pop index of call_data ".into(), stack_pop),
            ("stack push value of call_data".into(), stack_push),
            ("copy lookup 0".into(), copy_lookup_0),
            ("copy lookup 1".into(), copy_lookup_1),
            ("whether u64 overflow".into(), arithmetic_u64),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CALLDATALOAD);

        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);

        // 从栈上弹出一个元素标识从calldata读取数据的索引
        let (stack_pop_0, index) = current_state.get_pop_stack_row_value(trace);

        // 计算index是否u64溢出，并生成对应的arithmetic rows
        let (arith_rows, arith_values) = u64overflow::gen_witness::<F>(vec![index]);
        let offset = if arith_values[0] > 0.into() {
            (u64::MAX - 32).into()
        } else {
            index
        };
        // 生成copy_rows和state_rows，将copy_rows数据写入core_row_2
        // calldataload 读取的32字节数据分为两步进行，每次读取16byte由
        // core::Row的acc标识，所以将索引为15、31的copy row写入core_row_2;
        // 因为用u256类型来标识calldata上开始读取的index位置，存在u64溢出可能，
        // EVM规范对于u64溢出的情况读取32byte的0值，用arith_values[0]来标识是否
        // 溢出u64, >0标识存在溢出；
        // 将arithmetic_entry写入core电路
        let (copy_rows, mut state_rows) = current_state.get_calldata_load_rows::<F>(offset);
        let copy_row_0 = copy_rows.get(15).unwrap();
        let copy_row_1 = copy_rows.get(31).unwrap();
        core_row_2.insert_copy_lookup(0, copy_row_0);
        core_row_2.insert_copy_lookup(1, copy_row_1);
        core_row_2.insert_arithmetic_tiny_lookup(4, &arith_rows);

        // 计算push到栈上的数据 value, 并生成state row写入core_row_1
        // copy_row_0为前16byte，copy_row_1为后16byte，将copy_row_0
        // 左移128bit即16字节加上copy_row_1用来组成完整的copy数据
        let value = (copy_row_0.acc << 128) + copy_row_1.acc;
        let stack_push_0 = current_state.get_push_stack_row(trace, value);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);

        let core_row_0 = ExecutionState::CALLDATALOAD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        state_rows.extend([stack_pop_0, stack_push_0]);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            copy: copy_rows,
            arithmetic: arith_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CalldataloadGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use std::collections::HashMap;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    fn assign_and_constraint(stack: Stack) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            call_data: HashMap::new(),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        // 初始化calldata的数据
        current_state.call_data.insert(0, vec![0xab; 0x12]);

        let gas_left_before_exec =
            current_state.gas_left + OpcodeId::CALLDATALOAD.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, OpcodeId::CALLDATALOAD, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_index_overflow_u64() {
        // 设置calldataload的索引位置大于usize::max-32
        let mut index: U256 = usize::MAX.into();
        index = index - 30;
        let stack = Stack::from_slice(&[index]);
        assign_and_constraint(stack);
    }

    #[test]
    fn test_index_overflow_u128() {
        // 设置calldataload的索引位置大于u128
        let index: U256 = U256::MAX - 10;
        let stack = Stack::from_slice(&[index]);
        assign_and_constraint(stack);
    }

    #[test]
    fn test_in_range_and_padding() {
        // 设置calldataload的索引位置为1
        // assign_and_constraint 内部设置的calldata包含2个byte，
        // 因此会读取一个字节同时padding31个byte
        let stack = Stack::from_slice(&[1.into()]);
        assign_and_constraint(stack);
    }
}
