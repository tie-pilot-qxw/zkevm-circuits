use crate::constant::INDEX_STACK_POINTER;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::WitnessExecHelper;
use crate::witness::{assign_or_panic, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_binary_number::{simple_binary_number_assign, SimpleBinaryNumber};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 2;
const STACK_POINTER_DELTA: i32 = 1;
const PC_DELTA: u64 = 1;
const DUP_N_COL_IDX: usize = 31;
const OPCODE_BITS_START_COL_IDX: usize = 27;
const OPCODE_BITS_NUM: usize = 4;

/// DUP overview:
///   copy the value at the specified position in the stack and put the copied value on the top of the stack
///  examples:
///     stack: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
///     stack_top is 0, stack_bottom is 16
///     after execute DUP1: [1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
///     after execute DUP2: [2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
///     after execute DUP16: [16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
/// DUP Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+-----------------------------------+
/// |cnt| 8 col | 8 col | 8 col |               8 col               |
/// +---+-------+-------+-------+----------------------------------+
/// | 1 | STATE | STATE |       |                                  |
/// | 0 | DYNA_SELECTOR(20)   | AUX(7)  |DUP_N(1)| OPCODE_BITS(4)  |
/// +---+-------+-------+-------+----------------------------------+
/// DUP_N: the location of the target value to copy(if opcode is DUP1, then DUP_N is 1, if opcode is DUP16, then DUP_N is 16)
/// OPCODE_BITS: value range is 0~15, used to verify that the value of Opcode is within the range of DUP1~DUP16
pub struct DupGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for DupGadget<F>
{
    fn name(&self) -> &'static str {
        "DUP"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::DUP
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
        let dup_n = meta.query_advice(config.vers[DUP_N_COL_IDX], Rotation::cur());
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        let mut stack_operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                if i == 0 {
                    // if dup_n is 1, stack_pointer_delta is 0, which is the data obtained directly from the top of the stack
                    // if dup_n is n, stack_pointer_delta is n-1
                    0.expr() - (dup_n.clone() - 1.expr())
                } else {
                    1.expr()
                },
                i == 1,
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
                "stack_read_val hi = stack_push_val hi".into(),
                stack_operands[0][0].clone() - stack_operands[1][0].clone(),
            ),
            (
                "stack_read_val lo = stack_push_val lo".into(),
                stack_operands[0][1].clone() - stack_operands[1][1].clone(),
            ),
            (
                "dup_n = opcode-dup1+1".into(),
                dup_n - (opcode.clone() - OpcodeId::DUP1.as_u8().expr() + 1.expr()),
            ),
            (
                "opcode must be DUP1~DUP16".into(),
                opcode - OpcodeId::DUP1.as_u8().expr() - opcode_bits_val,
            ),
        ]);

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_read_val = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_push_val = query_expression(meta, |meta| config.get_state_lookup(meta, 1));

        vec![
            ("stack read val".into(), stack_read_val),
            ("stack push val".into(), stack_push_val),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op.is_dup());

        // the position of the value in the stack
        let dup_n = trace.op.postfix().unwrap() as usize;
        let (stack_read, value) =
            current_state.get_peek_stack_row_value(trace, trace.op.postfix().unwrap() as usize);

        assert_eq!(value, current_state.stack_top.unwrap());

        // copy the obtained value and put it on the top of the stack
        let stack_push = current_state.get_push_stack_row(trace, value);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_read, &stack_push]);
        let mut core_row_0 = ExecutionState::DUP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        assign_or_panic!(core_row_0[DUP_N_COL_IDX], U256::from(dup_n));

        // opcode bits
        simple_binary_number_assign(
            (trace.op.as_u64() - OpcodeId::DUP1.as_u64()) as usize,
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
            state: vec![stack_read, stack_push],
            arithmetic: vec![],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(DupGadget {
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
        // prepare a state to generate witness
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
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_dup() {
        // note: the values of the stack vector are in reverse order
        // if stack: [1, 2, 3, 4, 5], then stack_top is 5 and  stack_bottom is 1
        let stack_val: Vec<Word> = (1..=16).rev().map(|num| num.into()).collect();
        let opcode_vec: Vec<OpcodeId> = (OpcodeId::DUP1.as_u8()..=OpcodeId::DUP16.as_u8())
            .map(|opcode_u8| OpcodeId::from(opcode_u8))
            .collect();

        for i in 1..=16 {
            // split stack
            let s = Stack::from_slice(&stack_val[16 - i..16]);
            let opcode = opcode_vec[i - 1];
            let expect_stack_top = stack_val[16 - i];
            println!(
                "opcode:{}, expect_stack_top:{}, {:?}",
                opcode, expect_stack_top, s.0
            );
            run(opcode, s, expect_stack_top)
        }
    }
}
