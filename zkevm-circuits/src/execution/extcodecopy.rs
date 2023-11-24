// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, copy, Witness, WitnessExecHelper};
use eth_types::GethExecStep;
use eth_types::Word;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const ADDRESS_ZERO_COUNT: u32 = 12 * 8;
const STATE_STAMP_DELTA: u64 = 4;
const STACK_POINTER_DELTA: i32 = -4;
const PC_DELTA: u64 = 1;

/// Extcodecopy Execution State layout is as follows
/// where COPY means copy table lookup , 9 cols
/// ZEROCOPY means padding copy table lookup 9,cols
/// COPY_LEN_LO_INV ,ZERO_LEN_LO_INV means copy,zero length's multiplicative inverse;  
/// STATE means state table lookup,
/// STATE0 means account address,
/// STATE1 means memOffset
/// STATE2 means codeOffset
/// STATE3 means length
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | COPY   | ZEROCOPY | COPY_LEN_LO | COPY_LEN_LO_INV | ZERO_LEN_LO | ZERO_LEN_LO_INV |  
/// | 1 | STATE0| STATE1| STATE2| STATE3   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+

pub struct ExtcodecopyGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ExtcodecopyGadget<F>
{
    fn name(&self) -> &'static str {
        "EXTCODECOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::EXTCODECOPY
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let address = meta.query_advice(config.code_addr, Rotation::cur());
        let copy_entry = config.get_copy_lookup(meta);
        let padding_entry = config.get_copy_padding_lookup(meta);
        let (_, _, _, _, _, _, _, _, copy_lookup_len) =
            extract_lookup_expression!(copy, copy_entry.clone());
        let (_, _, _, _, _, _, _, _, copy_padding_lookup_len) =
            extract_lookup_expression!(copy, padding_entry.clone());
        let auxiliary_delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr()
                + copy_lookup_len.clone()
                + copy_padding_lookup_len.clone(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        let mut copy_operands = vec![];
        let mut copy_code_stamp_start = 0.expr();
        // stack constraints
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, tmp_stamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, entry);
            if i == 3 {
                copy_code_stamp_start = tmp_stamp.clone();
            }
            copy_operands.push([value_hi, value_lo]);
        }
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            code_addr: ExpressionOutcome::To(address.clone()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // copy constraints
        let copy_len_lo_inv = meta.query_advice(config.vers[19], Rotation(-2));
        let copy_len_lo = meta.query_advice(config.vers[18], Rotation(-2));
        let is_copy_zero_len = SimpleIsZero::new(
            &copy_len_lo,
            &copy_len_lo_inv,
            String::from("copy_length_lo"),
        );
        constraints.extend(is_copy_zero_len.get_constraints());

        constraints.extend(config.get_copy_contraints(
            copy::Type::Bytecode,
            copy_operands[0][0].clone() * pow_of_two::<F>(128) + copy_operands[0][1].clone(),
            copy_operands[2][1].clone(),
            0.expr(),
            copy::Type::Memory,
            call_id.clone(),
            copy_operands[1][1].clone(),
            copy_code_stamp_start.clone() + 1.expr(),
            copy_len_lo.clone(),
            is_copy_zero_len.expr(),
            copy_entry.clone(),
        ));

        // padding constraints
        let padding_len_lo = meta.query_advice(config.vers[20], Rotation(-2));
        let padding_len_lo_inv = meta.query_advice(config.vers[21], Rotation(-2));
        let is_padding_zero_len = SimpleIsZero::new(
            &padding_len_lo,
            &padding_len_lo_inv,
            String::from("padding_length_lo"),
        );
        constraints.extend(is_padding_zero_len.get_constraints());

        constraints.extend(config.get_copy_contraints(
            copy::Type::Zero,
            0.expr(),
            0.expr(),
            0.expr(),
            copy::Type::Memory,
            call_id.clone(),
            copy_operands[1][1].clone() + copy_lookup_len.clone(),
            copy_code_stamp_start.clone() + copy_lookup_len.clone() + 1.expr(),
            padding_len_lo.expr(),
            is_padding_zero_len.expr(),
            padding_entry.clone(),
        ));
        constraints.extend([
            (
                "stack top1 value_hi = 0".into(),
                copy_operands[1][0].clone() - 0.expr(),
            ),
            (
                "stack top2 value_hi = 0".into(),
                copy_operands[2][0].clone() - 0.expr(),
            ),
            (
                "stack top3 value_hi = 0".into(),
                copy_operands[3][0].clone() - 0.expr(),
            ),
            // todo: use arithmetic, when generating witness, stack top2 value_lo will be truncated to u64(input_copy_len)
            // (
            //     "stack top3 value_lo(input_len) = copy_lookup_len+padding_lookup_len".into(),
            //     copy_operands[3][1].clone() - copy_lookup_len - copy_padding_lookup_len,
            // ),
            // (
            //     "stack top3 value_lo(input_len) = copy_len_lo+padding_len_lo".into(),
            //     copy_operands[3][1].clone() - copy_len_lo - padding_len_lo,
            // ),
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
        let stack_lookup_3 = query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        let copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));
        let padding_copy_lookup =
            query_expression(meta, |meta| config.get_copy_padding_lookup(meta));

        vec![
            ("stack pop account address".into(), stack_lookup_0),
            ("stack pop mem offset".into(), stack_lookup_1),
            ("stack pop code offset".into(), stack_lookup_2),
            ("stack pop length".into(), stack_lookup_3),
            ("copy look up".into(), copy_lookup),
            ("padding look up".into(), padding_copy_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, address) = current_state.get_pop_stack_row_value(&trace);
        assert!(address.leading_zeros() >= ADDRESS_ZERO_COUNT);
        //let address_code = current_state.bytecode.get(&address).unwrap();
        let (stack_pop_1, mem_offset) = current_state.get_pop_stack_row_value(&trace);

        let (stack_pop_2, code_offset) = current_state.get_pop_stack_row_value(&trace);

        let (stack_pop_3, size) = current_state.get_pop_stack_row_value(&trace);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);

        let (copy_rows, mem_rows, input_length, padding_length, code_copy_length) =
            current_state.get_code_copy_rows(address, mem_offset, code_offset, size);

        let mut copy_row = &Default::default();
        if code_copy_length > 0 {
            copy_row = &copy_rows[0];
        }
        let mut padding_row = &Default::default();
        if padding_length > 0 {
            padding_row = &copy_rows[code_copy_length as usize]
        }
        core_row_2.insert_copy_lookup(copy_row, Some(padding_row));
        // code copy len
        assign_or_panic!(core_row_2.vers_18, U256::from(code_copy_length));
        let code_copy_len_lo = F::from(code_copy_length);
        let code_copy_lenlo_inv = U256::from_little_endian(
            code_copy_len_lo
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        assign_or_panic!(core_row_2.vers_19, code_copy_lenlo_inv);
        // padding copy len
        assign_or_panic!(core_row_2.vers_20, U256::from(padding_length));
        let padding_copy_len_lo = F::from(padding_length);
        let padding_copy_lenlo_inv = U256::from_little_endian(
            padding_copy_len_lo
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        assign_or_panic!(core_row_2.vers_21, padding_copy_lenlo_inv);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_pop_2, &stack_pop_3]);
        let core_row_0 = ExecutionState::EXTCODECOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_vec = vec![stack_pop_0, stack_pop_1, stack_pop_2, stack_pop_3];
        if mem_rows.len() > 0 {
            state_vec.extend(mem_rows);
        }
        Witness {
            copy: copy_rows,
            core: vec![core_row_2, core_row_1, core_row_0],
            state: state_vec,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ExtcodecopyGadget {
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
    fn assign_and_constraint_copy_no_padding() {
        run_prover(&[2.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_copy_padding() {
        run_prover(&[5.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_no_padding() {
        run_prover(&[0.into(), 0.into(), 0.into(), 0xaa.into()]);
    }

    #[test]
    fn assign_and_constraint_no_copy_only_padding() {
        run_prover(&[5.into(), 4.into(), 0.into(), 0xaa.into()]);
    }

    fn run_prover(words: &[Word]) {
        let stack = Stack::from_slice(words);
        let stack_pointer = stack.0.len();

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let mut code_vec = vec![];
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::PUSH1.as_u8());
        code_vec.push(OpcodeId::ADD.as_u8());
        current_state
            .bytecode
            .insert(0xaa.into(), code_vec.to_vec().into());
        let trace = prepare_trace_step!(0, OpcodeId::EXTCODECOPY, stack);
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
}
