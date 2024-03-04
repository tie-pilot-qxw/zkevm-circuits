use crate::arithmetic_circuit::operation;

use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::bitwise::Tag;
use crate::witness::exp;
use crate::witness::{arithmetic, bitwise, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;
const PC_DELTA: u64 = 1;
const BYTE_MAX_IDX: u8 = 31;
const EXP_OVERFLOW_IDX_BOUNDARY: u8 = 32;

///
/// BYTE gadget:
/// BYTE algorithm overview：
///    1.pop the two elements on top of the stack
///       stack_top0: byte_index、stack_top1: value
///    2.get the byte_index byte of value (big-endian order)
///    example:
///      PUSH5: 0x123456789a
///      PUSH1: 0x1d
///      BYTE
///      get a result is 0x56 (target_byte)
///      because it is big endian, 0x123456789a is actually 0x000000000000000000000000000000000000000000000000000000123456789a
///      so the 30th (0x1d) byte is 0x56
///  note: when byte_index > 31, the result (target_byte) is 0
///
/// Use bitwise subcircuit's sum2 to get target_byte
///    operand1: 0x000000000000000000000000000000000000000000000000000000123456789a
///    operand2: 0x0000000000000000000000000000000000000000000000000000000000ff0000
///    value: operand1 & operand2 --> 0x0000000000000000000000000000000000000000000000000000000000560000
///  we only need to traverse each byte of byte and add the value of each byte, the result (0x56) is the result we want (target_byte)
///  Bitwise circuit will help us complete the operation of `operadn1 & operand2`，we can get the value of sum2 from the bitwise table
///
/// How to construct operand2?
///    byte_index: 0x1d (29)
///    value: 0x000000000000000000000000000000000000000000000000000000123456789a
///
///    base_value: 100000000 (256)
///    pow_index: 31-byte_index
///    power: base_value^(pow_index) ---> 256^(31-29) ---> 256^2 ---> 10000000000000000
///    operand2: `255*power` ---> 255*10000000000000000 ---> 111111110000000000000000 ---> 0xff0000
///    Padding 0xff0000 to 32 bytes is the operanand2 we want: 0x0000000000000000000000000000000000000000000000000000000000ff0000
///
///
/// Table layout:
///     ARI: Arithmetic SUB lookup, src: Core circuit, target: Arithmetic circuit table, 9 columns
///     UNUSED0: unused column, 1 column
///     BW0: Bitwise low 16 byte lookup, src: Core circuit, target: Bitwise circuit table, 5 columns
///     BW1: Bitwise high 16 byte lookup, src: Core circuit, target: Bitwise circuit table, 5 columns
///     UNUSED1: 12 columns
///     STATE0:  State lookup(stack_top0), src: Core circuit, target: State circuit table, 8 columns
///     STATE1:  State lookup(stack_top1), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  stack lookup(push_value), src: Core circuit, target: State circuit table, 8 columns
///     EXP: EXP lookup, 6 columns
/// +---+---------+----------------+--------+---------+
/// |cnt| 8 col   |   8 col        | 8 col  |  8col   |
/// +---+---------+----------------+--------+---------+
/// | 2 |  ARI    | UNUSED0 | BW0  | BW1 | UNUSED1    |
/// | 1 | STATE0  |    STATE1      | STATE2 | EXP     |
/// | 0 |            DYNA_SELECTOR   | AUX            |
/// +---+---------+----------------+--------+---------+
///
pub struct ByteGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ByteGadget<F>
{
    fn name(&self) -> &'static str {
        "BYTE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::BYTE
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
        // get lookup value
        let (bitwise_lookup_lo_tag, bitwise_lookup_lo_acc_vers, bitwise_lookup_lo_sum_2) =
            extract_lookup_expression!(bitwise, config.get_bitwise_lookup(meta, 0));
        let (bitwise_lookup_hi_tag, bitwise_lookup_hi_acc_vers, bitwise_lookup_hi_sum_2) =
            extract_lookup_expression!(bitwise, config.get_bitwise_lookup(meta, 1));
        let (exp_lookup_base, exp_lookup_index, exp_lookup_pow) =
            extract_lookup_expression!(exp, config.get_exp_lookup(meta));

        // operand1 is 31
        // operand2 is byte_index(stack_top0)
        // result is exp_index
        // if operand1 + operand2 = result + carry
        // arithmetic_operands[0] is operand1_hi
        // arithmetic_operands[1] is operand1_lo
        // arithmetic_operands[2] is operand2_hi
        // arithmetic_operands[3] is operand2_lo
        // arithmetic_operands[4] is result_hi
        // arithmetic_operands[5] is result_lo
        // arithmetic_operands[6] is carry_hi
        // arithmetic_operands[7] is carry_lo
        // when carry_hi=1, the sub result is negative (very large number in F), we need to handle it by letting push_stack value = 0
        let (arithmetic_tag, arithmetic_operands) =
            extract_lookup_expression!(arithmetic, config.get_arithmetic_lookup(meta, 0));

        // auxiliary constraints
        let auxiliary_delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        let mut stack_operands = vec![];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                if i == 0 { 0 } else { -1 }.expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        constraints.extend([
            // stack_push_value is a byte, so value_hi is 0
            (
                "stack_push_value_hi == 0".into(),
                stack_operands[2][0].clone(),
            ),
            (
                "stack_push_value_lo == bitwise_lookup_hi_sum2 + bitwise_lookup_lo_sum2".into(),
                stack_operands[2][1].clone() - bitwise_lookup_hi_sum_2 - bitwise_lookup_lo_sum_2,
            ),
            // bitwise tag is And
            (
                "bitwise_lookup_lo_tag == and".into(),
                bitwise_lookup_lo_tag - (Tag::And as u8).expr(),
            ),
            (
                "bitwise_lookup_hi_tag == and".into(),
                bitwise_lookup_hi_tag - (Tag::And as u8).expr(),
            ),
            // bitwise operand1(acc_0) is stack_top1
            (
                "bitwise_lookup_acc0_hi == stack_top1_hi".into(),
                bitwise_lookup_hi_acc_vers[0].clone() - stack_operands[1][0].clone(),
            ),
            (
                "bitwise_lookup_acc0_lo == stack_top1_lo".into(),
                bitwise_lookup_lo_acc_vers[0].clone() - stack_operands[1][1].clone(),
            ),
            // arithmetic tag is sub
            (
                "arithmetic_tag = sub".into(),
                arithmetic_tag.clone() - (arithmetic::Tag::Sub as u8).expr(),
            ),
            // arithmetic_sub_operand1 is 31
            (
                "arithmetic_sub_operand1_hi = 0".into(),
                arithmetic_operands[0].clone(),
            ),
            (
                "arithmetic_sub_operand1_lo = 31".into(),
                arithmetic_operands[1].clone() - BYTE_MAX_IDX.expr(),
            ),
            // arithmetic_sub_operand1 is stack_top0(byte_index_hi)
            (
                "arithmetic_sub_operand2_hi = stack_top0_hi(byte_index_hi)".into(),
                arithmetic_operands[2].clone() - stack_operands[0][0].clone(),
            ),
            (
                "arithmetic_sub_operand2_lo = stack_top0_lo(byte_index_lo)".into(),
                arithmetic_operands[3].clone() - stack_operands[0][1].clone(),
            ),
            // exp_base is 256, so exp_base_hi is 0, exp_base_lo is 256
            ("exp_lookup_base_hi == 0".into(), exp_lookup_base[0].clone()),
            (
                "exp_lookup_base_lo == 256".into(),
                exp_lookup_base[1].clone() - 256.expr(),
            ),
            // exp_base.pow(index) is bitwise operand2(acc_1)
            (
                "exp_lookup_pow[0] * 255 = bitwise_lookup_acc1_hi".into(),
                exp_lookup_pow[0].clone() * 255.expr() - bitwise_lookup_hi_acc_vers[1].clone(),
            ),
            (
                "exp_lookup_pow[1] * 255 = bitwise_lookup_acc1_lo".into(),
                exp_lookup_pow[1].clone() * 255.expr() - bitwise_lookup_lo_acc_vers[1].clone(),
            ),
            // if carry_hi=0 it means stack_top0(byte_index) <= 31
            // so 31-byte_index result is normal and arithmetic_sub_result is exp_index
            (
                "arithmetic_sub_carry_hi=0 ==> arithmetic_sub_result_hi = exp_index_hi".into(),
                (1.expr() - arithmetic_operands[6].clone())
                    * (arithmetic_operands[4].clone() - exp_lookup_index[0].clone()),
            ),
            (
                "arithmetic_sub_carry_hi=0 ==> arithmetic_sub_result_low = exp_index_low".into(),
                (1.expr() - arithmetic_operands[6].clone())
                    * (arithmetic_operands[5].clone() - exp_lookup_index[1].clone()),
            ),
            // If carry_hi=1, it means stack_top0(byte_index) > 31, so 31-byte_index must overflow，
            // use 32 to calculate the overflow value of base.pow()，and the result is 0
            (
                "arithmetic_sub_carry_hi=1 ==> push_stack_value_hi=0".into(),
                arithmetic_operands[6].clone() * stack_operands[2][0].clone(),
            ),
            (
                "arithmetic_sub_carry_hi=1 ==> push_stack_value_low=0".into(),
                arithmetic_operands[6].clone() * stack_operands[2][1].clone(),
            ),
            (
                "arithmetic_sub_carry_hi=1 ==> exp_lookup_pow[0]=0".into(),
                arithmetic_operands[6].clone() * exp_lookup_pow[0].clone(),
            ),
            (
                "arithmetic_sub_carry_hi=1 ==> exp_lookup_pow[1]=0".into(),
                arithmetic_operands[6].clone() * exp_lookup_pow[1].clone(),
            ),
            (
                "arithmetic_sub_carry_hi=1 ==>  exp_index_hi=0".into(),
                arithmetic_operands[6].clone() * exp_lookup_index[0].clone(),
            ),
            (
                "arithmetic_sub_carry_hi=1 ==>  exp_index_low=32".into(),
                arithmetic_operands[6].clone()
                    * (exp_lookup_index[1].clone() - EXP_OVERFLOW_IDX_BOUNDARY.expr()),
            ),
        ]);
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
        let arithmetic_sub_lookup =
            query_expression(meta, |meta| config.get_arithmetic_lookup(meta, 0));
        let bitwise_lo_lookup = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 0));
        let bitwise_hi_lookup = query_expression(meta, |meta| config.get_bitwise_lookup(meta, 1));
        let exp_lookup = query_expression(meta, |meta| config.get_exp_lookup(meta));
        vec![
            ("stack lookup pop 0".into(), stack_lookup_0),
            ("stack lookup pop 1".into(), stack_lookup_1),
            ("stack lookup push".into(), stack_lookup_2),
            ("arithmetic sub lookup".into(), arithmetic_sub_lookup),
            ("bitwise lo lookup".into(), bitwise_lo_lookup),
            ("bitwise hi lookup".into(), bitwise_hi_lookup),
            ("exp_lookup".into(), exp_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::BYTE);

        let (stack_pop_0, byte_index) = current_state.get_pop_stack_row_value(&trace);
        let (stack_pop_1, value) = current_state.get_pop_stack_row_value(&trace);

        let value_hi = (value >> 128).as_u128();
        let value_lo = value.low_u128();

        // get arithmetic_sub rows
        // operand1: 31
        // operand2: byte_index(stack_top0)
        // result[0]:  value
        // result[1]: carry value
        // note: if byte_index > 31, then 31-byte_index will definitely overflow, and result[0] will be a very large value
        let byte_index_max = U256::from(BYTE_MAX_IDX);
        let (arithmetic_sub_rows, result) =
            operation::sub::gen_witness(vec![byte_index_max, byte_index]);

        // todo: calc base^index by exp circuit
        // exp circuit: base.pow(index) (base^index, if an overflow occurs in the exp circuit, the result is 0)
        // if byte_index > 31, result[0] will be a very large value, 256.pow(result[0]) will definitely overflow, and The result is 0,
        // so when result[0] is a large value, 32 is forced to be used for overflow operation
        let index = if byte_index > byte_index_max {
            U256::from(EXP_OVERFLOW_IDX_BOUNDARY)
        } else {
            result[0]
        };

        // calc exp power
        let base: U256 = U256::from(256);
        let (exp_pow, exp_rows, exp_arith_mul_rows) = exp::Row::from_operands(base, index);
        let value_index_byte_ff_lo = 255 * exp_pow.low_u128();
        let value_index_byte_ff_hi = 255 * (exp_pow >> 128).as_u128();

        // get bitwise rows
        let bitwise_lo_rows =
            bitwise::Row::from_operation::<F>(Tag::And, value_lo, value_index_byte_ff_lo);
        let bitwise_hi_rows =
            bitwise::Row::from_operation::<F>(Tag::And, value_hi, value_index_byte_ff_hi);

        // calc stack push value
        // stack pop index: index is big endian index
        // U256.byte(index): index is little endian index
        let value_target_byte_lo_sum = bitwise_lo_rows.last().unwrap().sum_2;
        let value_target_byte_hi_sum = bitwise_hi_rows.last().unwrap().sum_2;
        let value_target_byte = value_target_byte_lo_sum + value_target_byte_hi_sum;
        assert!(value_target_byte <= U256::from(255));

        let stack_push = current_state.get_push_stack_row(trace, value_target_byte);
        // assert value_target_byte
        let expect_value_target_byte = if byte_index >= U256::from(32) {
            U256::from(0)
        } else {
            U256::from(value.byte(31 - byte_index.as_usize()))
        };
        assert_eq!(expect_value_target_byte, value_target_byte);

        // generate core row
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        // columns: vers0 ~ vers8
        core_row_2.insert_arithmetic_lookup(0, &arithmetic_sub_rows);
        // columns: vers_10 ~ vers14
        core_row_2.insert_bitwise_lookups(0, &bitwise_lo_rows.last().unwrap());
        // columns: vers_15 ~ vers_19
        core_row_2.insert_bitwise_lookups(1, &bitwise_hi_rows.last().unwrap());

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push]);
        core_row_1.insert_exp_lookup(base, U256::from(index), exp_pow);

        let core_row_0 = ExecutionState::BYTE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut arithmetic_rows = vec![];
        arithmetic_rows.extend(arithmetic_sub_rows);
        arithmetic_rows.extend(exp_arith_mul_rows);

        let mut bitwise_rows = vec![];
        bitwise_rows.extend(bitwise_lo_rows);
        bitwise_rows.extend(bitwise_hi_rows);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push],
            bitwise: bitwise_rows,
            arithmetic: arithmetic_rows,
            exp: exp_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ByteGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use std::fs::File;
    generate_execution_gadget_test_circuit!();

    fn assign_and_constraint(operand1: U256, operand2: U256) {
        let stack = Stack::from_slice(&[operand2, operand1]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0.into()),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::BYTE, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
        let mut buf = std::io::BufWriter::new(File::create("demo.html").unwrap());
        witness.write_html(&mut buf);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_assign_and_constraint1() {
        let operand1 = U256::from(31);
        let operand2 = U256::from(0x123456789a_u128);
        assign_and_constraint(operand1, operand2)
    }

    #[test]
    fn test_assign_and_constraint2() {
        let operand1 = U256::from(33);
        let operand2 = U256::from(0x123456789a_u128);
        assign_and_constraint(operand1, operand2)
    }

    #[test]
    fn test_assign_and_constraint3() {
        let operand1 = U256::from(U256::MAX);
        let operand2 = U256::from(0x123456789a_u128);
        assign_and_constraint(operand1, operand2)
    }
}
