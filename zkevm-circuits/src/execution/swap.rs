use crate::constant::INDEX_STACK_POINTER;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_binary_number::{simple_binary_number_assign, SimpleBinaryNumber};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 4;
const PC_DELTA: u64 = 1;
const SWAP_N_COL_IDX: usize = 31;
const OPCODE_BITS_START_COL_IDX: usize = 27;
const OPCODE_BITS_NUM: usize = 4;

/// SWAP overview:
///  SWAP is an instruction used to swap the positions of elements on the stack.
///  SWAPn: Swap the top of the stack with the nth element from the top of the stack
/// example:
///    stack: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
///    stack_top is 0, stack_bottom is 16
///    SWAP1: the positions of the values 0 and 1 will be swapped
///         result: [1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
///
///    SWAP16: the positions of the values 0 and 16 will be swapped
///         result: [16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]
///
/// SWAP Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+-----------------------------------+
/// |cnt| 8 col | 8 col | 8 col |               8 col               |
/// +---+-------+-------+-------+----------------------------------+
/// | 1 | STATE | STATE | STATE |  STATE                           |
/// | 0 | DYNA_SELECTOR(20)   | AUX(7)  |SWAP_N(1)| OPCODE_BITS(4) |
/// +---+-------+-------+-------+------------------------------+
/// SWAP_N: The position of the second value(if opcode is SWAP1, then SWAP_N is 1, if opcode is SWAP16, then SWAP_N is 16)
/// OPCODE_BITS: value range is 0~15, used to verify that the value of Opcode is within the range of SWAP1~SWAP16
pub struct SwapGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for SwapGadget<F>
{
    fn name(&self) -> &'static str {
        "SWAP"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::SWAP
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
        let swap_n = meta.query_advice(config.vers[SWAP_N_COL_IDX], Rotation::cur());
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        // stack constraints
        let mut stack_operands = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            let stack_pointer_delta = if i == 0 || i == 3 {
                0.expr()
            } else {
                0.expr() - swap_n.clone()
            };
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta,
                i > 1,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        let opcode_bits: [Expression<F>; OPCODE_BITS_NUM] = [
            meta.query_advice(config.vers[OPCODE_BITS_START_COL_IDX], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_BITS_START_COL_IDX + 1], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_BITS_START_COL_IDX + 2], Rotation::cur()),
            meta.query_advice(config.vers[OPCODE_BITS_START_COL_IDX + 3], Rotation::cur()),
        ];

        // used to verify that the value of Opcode is within the range of SWAP1~SWAP16
        let simple_binary_number = SimpleBinaryNumber::new(&opcode_bits);
        constraints.extend(simple_binary_number.get_constraints());
        let opcode_bits_val = simple_binary_number.value();

        constraints.extend([
            (
                "stack_read_a hi = stack_write_a hi".into(),
                stack_operands[0][0].clone() - stack_operands[2][0].clone(),
            ),
            (
                "stack_read_a lo = stack_write_a lo".into(),
                stack_operands[0][1].clone() - stack_operands[2][1].clone(),
            ),
            (
                "stack_read_b hi = stack_write_b hi".into(),
                stack_operands[1][0].clone() - stack_operands[3][0].clone(),
            ),
            (
                "stack_read_b lo = stack_write_b lo".into(),
                stack_operands[1][1].clone() - stack_operands[3][1].clone(),
            ),
            (
                "swap_n = opcode-swap1+1".into(),
                swap_n - (opcode.clone() - OpcodeId::SWAP1.as_u8().expr() + 1.expr()),
            ),
            (
                "opcode must be SWAP1~SWAP16".into(),
                opcode - OpcodeId::SWAP1.as_u8().expr() - opcode_bits_val,
            ),
        ]);
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_read_a = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_read_b = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_write_a = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let stack_write_b = query_expression(meta, |meta| config.get_state_lookup(meta, 3));

        vec![
            ("stack pop a".into(), stack_read_a),
            ("stack pop b".into(), stack_read_b),
            ("stack overwrite push a".into(), stack_write_a),
            ("stack overwrite push b".into(), stack_write_b),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op.is_swap());

        // get two values from the stack
        let swap_n = trace.op.postfix().unwrap() as usize;
        let b_index = swap_n + 1;

        let (stack_read_a, value_a) = current_state.get_peek_stack_row_value(trace, 1);
        let (stack_read_b, value_b) = current_state.get_peek_stack_row_value(trace, b_index);

        // swap the positions of two values in an overwriting manner
        let stack_write_a = current_state.get_overwrite_stack_row(&trace, b_index, value_a);
        let stack_write_b = current_state.get_overwrite_stack_row(&trace, 1, value_b);

        assert_eq!(current_state.stack_top.unwrap(), value_b);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert state lookups
        core_row_1.insert_state_lookups([
            &stack_read_a,
            &stack_read_b,
            &stack_write_a,
            &stack_write_b,
        ]);

        let mut core_row_0 = ExecutionState::SWAP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        assign_or_panic!(core_row_0[SWAP_N_COL_IDX], U256::from(swap_n));

        // opcode bits
        simple_binary_number_assign(
            (trace.op.as_u64() - OpcodeId::SWAP1.as_u64()) as usize,
            [
                &mut core_row_0.vers_27,
                &mut core_row_0.vers_28,
                &mut core_row_0.vers_29,
                &mut core_row_0.vers_30,
            ],
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_read_a, stack_read_b, stack_write_a, stack_write_b],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(SwapGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use eth_types::Word;
    generate_execution_gadget_test_circuit!();

    fn run(opcode: OpcodeId, stack: Stack, expect_stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(expect_stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, opcode, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + INDEX_STACK_POINTER] =
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
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_swap() {
        let max_num = 16;
        // note: the values of the stack vector are in reverse order
        // if stack: [1, 2, 3, 4, 5], then stack_top is 5 and  stack_bottom is 1
        let stack_val: Vec<Word> = (0..=max_num).rev().map(|num| num.into()).collect();
        let opcode_vec: Vec<OpcodeId> = (OpcodeId::SWAP1.as_u8()..=OpcodeId::SWAP16.as_u8())
            .map(|opcode_u8| OpcodeId::from(opcode_u8))
            .collect();

        for i in 1..=max_num {
            // split stack
            let s = Stack::from_slice(&stack_val[max_num - i..=max_num]);
            let opcode = opcode_vec[i - 1];
            let expect_stack_top = stack_val[max_num - i];
            println!(
                "opcode:{}, expect_stack_top:{}, {:?}",
                opcode, expect_stack_top, s.0
            );
            run(opcode, s, expect_stack_top)
        }
    }
}
