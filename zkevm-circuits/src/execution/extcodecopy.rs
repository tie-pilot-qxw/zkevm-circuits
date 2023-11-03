// Code generated - COULD HAVE BUGS!
// This file is a generated execution gadget definition.

use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
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
/// | 2 | COPY   |
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
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let (
            copy_lookup_src_type,
            copy_lookup_src_id,
            copy_lookup_src_pointer,
            _,
            copy_lookup_dst_type,
            copy_lookup_dst_id,
            copy_lookup_dst_pointer,
            copy_lookup_dst_stamp,
            copy_lookup_len,
        ) = extract_lookup_expression!(copy, config.get_copy_lookup(meta));
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + copy_lookup_len.clone(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let mut copy_operands = vec![];
        let mut first_state_stamps = vec![];
        // stack constraints
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                (i).expr() * (-1).expr(),
                false,
            ));
            let (_, tmpStamp, value_hi, value_lo, _, _, _, _) =
                extract_lookup_expression!(state, entry);
            if i == 3 {
                first_state_stamps.push(tmpStamp);
            }
            let tmp_expression = value_hi * pow_of_two::<F>(128) + value_lo;
            copy_operands.push(tmp_expression);
        }
        // copy constraints
        constraints.extend([
            (
                "copy src_type".into(),
                copy_lookup_src_type.clone() - (copy::Type::Bytecode as u8).expr(),
            ),
            (
                "copy dst_type".into(),
                copy_lookup_dst_type.clone() - (copy::Type::Memory as u8).expr(),
            ),
            ("copy dst_id".into(), copy_lookup_dst_id.clone() - call_id),
            (
                "copy dst_stamp".into(),
                copy_lookup_dst_stamp.clone() - first_state_stamps[0].clone() - 1.expr(),
            ),
            (
                "copy src_id".into(),
                copy_lookup_src_id.clone() - copy_operands[0].clone(),
            ),
            (
                "copy dst_pointer".into(),
                copy_lookup_dst_pointer.clone() - copy_operands[1].clone(),
            ),
            (
                "copy src_pointer".into(),
                copy_lookup_src_pointer.clone() - copy_operands[2].clone(),
            ),
            (
                "copy len".into(),
                copy_lookup_len.clone() - copy_operands[3].clone(),
            ),
        ]);
        // pc & opcode constrains
        constraints.extend([
            (
                "opcode".into(),
                opcode - OpcodeId::EXTCODECOPY.as_u8().expr(),
            ),
            ("next pc".into(), pc_next - pc_cur - PC_DELTA.expr()),
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
        vec![
            ("stack pop account address".into(), stack_lookup_0),
            ("stack pop mem offset".into(), stack_lookup_1),
            ("stack pop code offset".into(), stack_lookup_2),
            ("stack pop  length".into(), stack_lookup_3),
            ("copy look up".into(), copy_lookup),
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

        core_row_2.insert_copy_lookup(&copy::Row {
            byte: 0.into(), //not used
            src_type: copy::Type::Bytecode,
            src_id: address,
            src_pointer: code_offset,
            src_stamp: None, // not used
            dst_type: copy::Type::Memory,
            dst_id: current_state.call_id.into(),
            dst_pointer: mem_offset,
            dst_stamp: current_state.state_stamp.into(),
            len: size,
            cnt: 0.into(), // not used
        });

        let (copy_rows, mem_rows) = current_state.get_code_copy_rows(
            address,
            mem_offset.as_usize(),
            code_offset.as_usize(),
            size.as_usize(),
        );

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_pop_2, &stack_pop_3]);
        let core_row_0 = ExecutionState::EXTCODECOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut state_vec = vec![stack_pop_0, stack_pop_1, stack_pop_2, stack_pop_3];
        state_vec.extend_from_slice(&mem_rows);
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
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0.into(), 1.into(), 2.into(), 3.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            ..WitnessExecHelper::new()
        };
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
