use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, bitwise, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::ops::Add;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const CORE_ROW_1_START_COL_IDX: usize = 24;
/// AndOrXORGadget deal OpCodeId:{AND,OR,XOR}
/// STATE0 record operand_0
/// STATE1 record operand_1
/// STATE2 record result
/// TAG_SEL 3 columns, And Or Xor ,depends on opcode , only 1, else 0
/// BW0 bitwise hi lookup , or operation, record operand_0 hi operator operand_1 hi ,originated from column 10
/// BW1 bitwise lo lookup , or operation, record operand_0 lo operator operand_1 lo ,originated from column 15
/// BW2 bitwise hi lookup , and operation, record operand_0 hi operator operand_1 hi ,originated from column 20
/// BW3 bitwise lo lookup , and operation, record operand_0 lo operator operand_1 lo ,originated from column 25
/// +---+-------+-------+-------+-----------+
/// |cnt| 8 col | 8 col | 8 col |    8 col  |
/// +---+-------+-------+-------+-----------+
/// | 2 | UNUSED(10) |BW0|BW1|BW2|BW3       |
/// | 1 | STATE0|STATE1 |STATE2 | TAG_SEL(3)|                                                                  |
/// | 0 | DYNA_SELECTOR   | AUX             |
/// +---+-------+-------+-------+-----------|
pub struct AndOrXorGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for AndOrXorGadget<F>
{
    fn name(&self) -> &'static str {
        "AND_OR_XOR"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::AND_OR_XOR
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
        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            // AND, OR, XOR gas cost is FASTEST,
            // Only one of the representatives is used here
            gas_left: ExpressionOutcome::Delta(-OpcodeId::AND.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_next_single_purpose_constraints(meta, core_single_delta));
        // stack_operands [operand_0 hi, operand_0 lo , operand_1 hi, operand_1 lo,result hi,result lo]
        let mut stack_operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        // stack constraints
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }
        // selector constraints
        // tag selector at row cnt = 1
        let selector = SimpleSelector::new(&[
            // AND: vers[24] at row cnt = 1
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX], Rotation::prev()),
            // OR: vers[25] at row cnt = 1
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 1], Rotation::prev()),
            // XOR: vers[26] at row cnt = 1
            meta.query_advice(config.vers[CORE_ROW_1_START_COL_IDX + 2], Rotation::prev()),
        ]);
        constraints.extend(selector.get_constraints());
        // bitwise constraints
        // i = 0/2: bitwise hi lookup
        //        bitwise hi lookup acc 0 = stack_operands[0][0]
        //        bitwise hi lookup acc 1 = stack_operands[1][0]
        //        bitwise hi lookup acc 2 = stack_operands[2][0]
        // i = 1/3: bitwise lo lookup
        //        bitwise lo lookup acc 0 = stack_operands[0][1]
        //        bitwise lo lookup acc 1 = stack_operands[1][1]
        //        bitwise lo lookup acc 2 = stack_operands[2][1]
        let mut or_and_operands = vec![];
        for i in 0..4 {
            // get bitwise entry
            let bitwise_entry = config.get_bitwise_lookup(meta, i);
            let (bitwise_tag, bitwise_acc, _) = extract_lookup_expression!(bitwise, bitwise_entry);
            // bitwise tag constraints
            let tag = if i < 2 {
                // 0,1 bitwise or operations
                bitwise::Tag::Or
            } else {
                // 0,1 bitwise and operations
                bitwise::Tag::And
            };
            constraints.extend([(
                "bitwise tag constraints".into(),
                bitwise_tag.clone() - (tag as usize).expr(),
            )]);
            let stack_index = i % 2;
            // bitwise acc 0 = stack_operands[0][i]
            constraints.extend([(
                format!("bitwise{} acc 0 = stack_operands{}{}", i, 0, stack_index),
                bitwise_acc[0].clone() - stack_operands[0][stack_index].clone(),
            )]);
            // bitwise acc 1 = stack_operands[1][i]
            constraints.extend([(
                format!("bitwise{} acc 1 = stack_operands{}{}", i, 1, stack_index),
                bitwise_acc[1].clone() - stack_operands[1][stack_index].clone(),
            )]);
            // store bitwise result in vec
            or_and_operands.push(bitwise_acc[2].clone());
        }
        // result constraints
        // if opcode is xor:
        //  stack_operands[2][0] = bitwise_hi_or_result - bitwise_hi_and_result
        //  stack_operands[2][1] = bitwise_lo_or_result - bitwise_lo_and_result
        // if opcode is or:
        //  stack_operands[2][0] = bitwise_hi_or_result
        //  stack_operands[2][1] = bitwise_lo_or_result
        // if opcode is and
        //  stack_operands[2][0] = bitwise_hi_and_result
        //  stack_operands[2][1] = bitwise_lo_and_result
        constraints.extend([
            (
                "result hi stack_operands[2][0] constraint".into(),
                selector.select(&[
                    stack_operands[2][0].clone() - or_and_operands[2].clone(), // result hi == bitwise_hi_and_result
                    stack_operands[2][0].clone() - or_and_operands[0].clone(), // result hi == bitwise_hi_or_result
                    stack_operands[2][0].clone()
                        - (or_and_operands[0].clone() - or_and_operands[2].clone()), // result hi == bitwise_hi_or_result - bitwise_hi_and_result
                ]),
            ),
            (
                "result lo stack_operands[2][1] constraint".into(),
                selector.select(&[
                    stack_operands[2][1].clone() - or_and_operands[3].clone(), // result lo == bitwise_lo_and_result
                    stack_operands[2][1].clone() - or_and_operands[1].clone(), // result lo == bitwise_lo_or_result
                    stack_operands[2][1].clone()
                        - (or_and_operands[1].clone() - or_and_operands[3].clone()), // result lo == bitwise_lo_or_result - bitwise_lo_and_result
                ]),
            ),
        ]);

        // opcode constraints
        constraints.extend([(
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::AND.as_u8().expr(),
                opcode.clone() - OpcodeId::OR.as_u8().expr(),
                opcode.clone() - OpcodeId::XOR.as_u8().expr(),
            ]),
        )]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        // stack lookups
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        // bitwise hi or lookups
        let bitwise_lookup_or_hi =
            query_expression(meta, |meta| config.get_bitwise_lookup(meta, 0));
        // bitwise lo or lookups
        let bitwise_lookup_or_lo =
            query_expression(meta, |meta| config.get_bitwise_lookup(meta, 1));
        // bitwise hi and lookups
        let bitwise_lookup_and_hi =
            query_expression(meta, |meta| config.get_bitwise_lookup(meta, 2));
        // bitwise lo and lookups
        let bitwise_lookup_and_lo =
            query_expression(meta, |meta| config.get_bitwise_lookup(meta, 3));
        let lookups = vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("bitwise hi or lookup".into(), bitwise_lookup_or_hi),
            ("bitwise lo or lookup".into(), bitwise_lookup_or_lo),
            ("bitwise hi and lookup".into(), bitwise_lookup_and_hi),
            ("bitwise lo and lookup".into(), bitwise_lookup_and_lo),
        ];
        lookups
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // operand a
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value(&trace);
        // operand b
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value(&trace);
        // c is result
        let c = current_state.stack_top.unwrap_or_default();
        // bit_wise_rows = [bitwise hi, bitwise lo]
        let mut bit_wise_rows = vec![];

        // get operands_hi bitwise or rows
        let bitwise_rows_or_hi = bitwise::Row::from_operation::<F>(
            bitwise::Tag::Or,
            (a >> 128).as_u128(),
            (b >> 128).as_u128(),
        );
        // get operands_lo bitwise or rows
        let bitwise_rows_or_lo =
            bitwise::Row::from_operation::<F>(bitwise::Tag::Or, a.low_u128(), b.low_u128());
        // get operands_hi bitwise and rows
        let bitwise_rows_and_hi = bitwise::Row::from_operation::<F>(
            bitwise::Tag::And,
            (a >> 128).as_u128(),
            (b >> 128).as_u128(),
        );
        // get operands_lo bitwise and rows
        let bitwise_rows_and_lo =
            bitwise::Row::from_operation::<F>(bitwise::Tag::And, a.low_u128(), b.low_u128());
        // result = (a || b) - (a && b), for a || b is greater than a && b in high 128 and lower 128
        let or_result = (bitwise_rows_or_hi.last().unwrap().acc_2 << 128)
            .add(bitwise_rows_or_lo.last().unwrap().acc_2);
        let and_result = (bitwise_rows_and_hi.last().unwrap().acc_2 << 128)
            .add(bitwise_rows_and_lo.last().unwrap().acc_2);
        let xor_result = or_result - and_result;
        let (result, index) = match trace.op {
            OpcodeId::AND => (and_result, 0usize),
            OpcodeId::OR => (or_result, 1),
            OpcodeId::XOR => (xor_result, 2),
            _ => panic!("not and,or,xor"),
        };
        assert_eq!(c, result);
        let stack_push_0 = current_state.get_push_stack_row(trace, c);
        // insert bitwise lookups
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // bitwise or hi lookup
        core_row_2.insert_bitwise_lookups(0, &bitwise_rows_or_hi.last().unwrap());
        // bitwise or lo lookup
        core_row_2.insert_bitwise_lookups(1, &bitwise_rows_or_lo.last().unwrap());
        // bitwise and hi lookup
        core_row_2.insert_bitwise_lookups(2, &bitwise_rows_and_hi.last().unwrap());
        // bitwise and lo lookup
        core_row_2.insert_bitwise_lookups(3, &bitwise_rows_and_lo.last().unwrap());
        // fill bit_wise_rows
        // bitwise or hi
        bit_wise_rows.extend(bitwise_rows_or_hi);
        // bitwise or lo
        bit_wise_rows.extend(bitwise_rows_or_lo);
        // bitwise and hi
        bit_wise_rows.extend(bitwise_rows_and_hi);
        // bitwise and lo
        bit_wise_rows.extend(bitwise_rows_and_lo);
        // insert state lookups
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        simple_selector_assign(
            &mut core_row_1,
            [
                CORE_ROW_1_START_COL_IDX,
                CORE_ROW_1_START_COL_IDX + 1,
                CORE_ROW_1_START_COL_IDX + 2,
            ],
            index,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        let core_row_0 = ExecutionState::AND_OR_XOR.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            bitwise: bit_wise_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(AndOrXorGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(opcode: OpcodeId, stack: Stack, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + OpcodeId::AND.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, opcode, stack);
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
    fn run_and() {
        // 0xffff & 0xff00 = 0xff00
        run(
            OpcodeId::AND,
            Stack::from_slice(&[0xffff.into(), 0xff00.into()]),
            0xff00.into(),
        )
    }
    #[test]
    fn run_or() {
        // 0xffff | 0xff00 = 0x00ff
        run(
            OpcodeId::OR,
            Stack::from_slice(&[0xffff.into(), 0xff00.into()]),
            0xffff.into(),
        )
    }

    #[test]
    fn run_xor() {
        // 0xffff ^ 0xff00 = 0x00ff
        run(
            OpcodeId::XOR,
            Stack::from_slice(&[0xffff.into(), 0xff00.into()]),
            0xff.into(),
        )
    }
}
