use crate::constant::NUM_AUXILIARY;
use crate::execution::{
    call_2, Auxiliary, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition,
    ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, copy, state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub(super) const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: usize = 3;
const STACK_POINTER_DELTA: i32 = 0; // we let stack pointer change at call5

/// call_1..call_4为 CALL指令调用之前的操作，即此时仍在父CALL环境，
/// 读取接下来CALL需要的各种操作数，每个call_* gadget负责不同的操作数.
/// call_1 读取argsOffset，argsLength操作数；并生成新CALL的call_id
/// |gas | addr | value | argsOffset | argsLength | retOffset | retLength
///
///
/// Call1 is the first step of opcode CALL
/// Algorithm overview:
///     1. read args_len, args_offset from stack (temporarily not popped)
///     2. set callcontext's calldata_size = args_len
///     3. copy memory[args_offset:args_offset + args_len] to calldata
/// Table layout:
///     STATE1:  State lookup(stack read args_offset), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack read args_len), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  State lookup(call_context write calldata_size), src: Core circuit, target: State circuit table, 8 columns
///     COPY:   Copy lookup(copy args_len bytes from memory to calldata), src:Core circuit, target:Copy circuit table, 11 columns
///     LEN_INV: the inverse of copy lookup's len, used to check whether copy lookup's len == 0
///     STATE_STAMP_INIT: the state stamp just before the execution of opcode CALL, which will be used by the next execution states
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY  |                          |
/// | 1 | STATE1| STATE2| STATE3|LEN_INV(1)|
/// | 0 | DYNA_SELECTOR   | AUX | STATE_STAMP_INIT(1) |
/// +---+-------+-------+-------+----------+
///
/// Note: call_context write's call_id should be callee's
pub struct Call1Gadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for Call1Gadget<F>
{
    fn name(&self) -> &'static str {
        "CALL_1"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALL_1
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, super::call_2::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let call_id_cur = meta.query_advice(config.call_id, Rotation::cur());
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let stamp_init_for_next_gadget = meta.query_advice(
            config.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY],
            Rotation::cur(),
        );
        let call_id_new = state_stamp_prev.clone() + 1.expr();

        let copy_entry = config.get_copy_lookup(meta);
        let (_, _, _, _, _, _, _, _, _, len, _) =
            extract_lookup_expression!(copy, copy_entry.clone());
        let delta = AuxiliaryOutcome {
            // 读取CALL指令调用需要的args，因为相同的args写了两份，所以需要len*2
            // 第一次args: 记录从memory读取数据
            // 第二次args: 记录数据写入calldata
            state_stamp: ExpressionOutcome::Delta(
                STATE_STAMP_DELTA.expr() + len.clone() * 2.expr(),
            ),
            // 未进行出栈操作，约束当前stack pointer与上个gadget相同
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        // append auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append stack constraints and call_context constraints
        let mut operands = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            if i < 2 {
                // 从core电路中获取argsOffset、argsLength状态进行约束
                // |gas | addr | value | argsOffset | argsLength | retOffset | retLength
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    // the position of args_offset and args_len are -3 and -5 respectively.
                    if i == 0 { -3 } else { -4 }.expr(),
                    false,
                ));
            } else {
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    true,
                    (state::CallContextTag::CallDataSize as u8).expr(),
                    call_id_new.clone(),
                ));
            }
            // 记录状态中的操作数
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        // CALL指令的两个操作数
        let args_offset = &operands[0];
        let args_len = &operands[1];
        // calldata_size=args_len
        let calldata_size = &operands[2];
        // append constraints for state_lookup's values
        constraints.extend([
            // 在EVM中堆栈、CALLDATA的偏移量、数据长度用128bit足以标识，
            // 所以约束高128bit为0
            ("offset_hi == 0".into(), args_offset[0].clone()),
            ("len_hi == 0".into(), args_len[0].clone()),
            ("calldata_size_hi == 0".into(), calldata_size[0].clone()),
            // calldata_size = args len
            (
                "len_lo == calldata_size_lo".into(),
                args_len[1].clone() - calldata_size[1].clone(),
            ),
        ]);
        //append copy constraints
        let len_lo_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let is_zero_len = SimpleIsZero::new(&args_len[1], &len_lo_inv, String::from("length_lo"));
        constraints.append(&mut is_zero_len.get_constraints());

        // 添加copy约束，从memory copy数据至calldata
        let (_, stamp, ..) = extract_lookup_expression!(state, config.get_state_lookup(meta, 2));
        constraints.append(&mut config.get_copy_constraints(
            copy::Tag::Memory,
            call_id_cur,
            args_offset[1].clone(),
            // +1.expr() after state row is generated, the stamp+=1 affected,
            // thus subsequent copy_row start at stamp+=1.
            stamp.clone() + 1.expr(),
            copy::Tag::Calldata,
            call_id_new,
            0.expr(),
            stamp + args_len[1].clone() + 1.expr(),
            None,
            args_len[1].clone(),
            is_zero_len.expr(),
            None,
            copy_entry,
        ));
        // append opcode constraint
        constraints.extend([("opcode".into(), opcode - OpcodeId::CALL.as_u8().expr())]);
        constraints.extend([(
            "state_init_for_next_gadget correct".into(),
            stamp_init_for_next_gadget - state_stamp_prev,
        )]);
        // append core single purpose constraints
        let core_single_delta: CoreSinglePurposeOutcome<F> = CoreSinglePurposeOutcome {
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        // next state is CALL_2 constraints
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::CALL_2, call_2::NUM_ROW, None)],
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
        let call_context_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));

        vec![
            ("stack read args_offset".into(), stack_lookup_0),
            ("stack read args_len".into(), stack_lookup_1),
            ("write calldatasize".into(), call_context_lookup),
            ("calldata copy lookup".into(), copy_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // 为CALL指令生成call_id
        current_state.call_id_new = current_state.state_stamp + 1;
        let stamp_init = current_state.state_stamp;
        // 读取CALL指令栈上操作数 argsOffset，argsLength（Note：非弹出栈操作）
        let (stack_read_0, args_offset) = current_state.get_peek_stack_row_value(trace, 4);
        let (stack_read_1, args_len) = current_state.get_peek_stack_row_value(trace, 5);

        // 记录CALL指令需要的参数长度
        let call_context_write_row = current_state.get_call_context_write_row(
            state::CallContextTag::CallDataSize,
            args_len,
            current_state.call_id_new,
        );
        //update current_state's call_data_size
        current_state
            .call_data_size
            .insert(current_state.call_id_new, args_len);
        //generate copy rows and memory read rows and calldata write rows
        // copy rows: 从调用方的memory 拷贝数据至被调方的calldata
        // state_rows：copy的数据记录两份，第一份为从memory的copy，第二份为写入calldata
        let (copy_rows, mut state_rows) =
            current_state.get_calldata_write_rows::<F>(trace, args_offset, args_len);
        // generate core rows，写入copy数据
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        // insert lookup: Core ---> Copy
        if args_len.is_zero() {
            core_row_2.insert_copy_lookup(
                0,
                &copy::Row {
                    byte: 0.into(),
                    src_type: copy::Tag::default(),
                    src_id: 0.into(),
                    src_pointer: 0.into(),
                    src_stamp: 0.into(),
                    dst_type: copy::Tag::default(),
                    dst_id: 0.into(),
                    dst_pointer: 0.into(),
                    dst_stamp: 0.into(),
                    cnt: 0.into(),
                    len: 0.into(),
                    acc: 0.into(),
                },
            );
        } else {
            core_row_2.insert_copy_lookup(0, copy_rows.get(0).unwrap());
        }

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // core_row_1 写入3个状态的数据和args_len的相反数
        core_row_1.insert_state_lookups([&stack_read_0, &stack_read_1, &call_context_write_row]);
        // calculate and assign len_inv
        let len_lo_inv = U256::from_little_endian(
            F::from_u128(args_len.low_u128())
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        assign_or_panic!(core_row_1.vers_24, len_lo_inv);

        let mut core_row_0 = ExecutionState::CALL_1.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        // core_row_0写入stamp_init状态
        assign_or_panic!(core_row_0.vers_27, stamp_init.into());
        state_rows.extend([stack_read_0, stack_read_1, call_context_write_row]);
        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(Call1Gadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[
            0x05.into(),   // ret_length
            0x2222.into(), // ret_offset
            0x04.into(),   // arg_length
            0x1111.into(), // arg_offset
            0x01.into(),   // value
            0x1234.into(), // addr
            0x01.into(),   // gas
        ]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 4];

        let mut current_state = WitnessExecHelper {
            stack_pointer,
            stack_top: None,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::CALL, stack);
        trace.memory.0 = vec![0; 0x1114];
        // 写入4字节的arg内存，因为stack中arg的长度为4
        for i in 0..4 {
            trace.memory.0.insert(0x1111 + i, value_vec[i]);
        }

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let row = ExecutionState::CALL_2.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
