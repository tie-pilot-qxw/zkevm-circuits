use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const PC_DELTA: usize = 1;
const STATE_STAMP_DELTA: usize = 3;
const STACK_POINTER_DELTA: i32 = -3;

/// CALLDATACOPY copy message data from calldata to memory in EVM.
///
/// CALLDATACOPY Execution State layout is as follows
/// where STATE means state table lookup (dst_offset, src_offset, length),
/// LENGTH means retrive data length from calldata,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | LENGTH|       |       |          |
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct CalldatacopyGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CalldatacopyGadget<F>
{
    fn name(&self) -> &'static str {
        "CALLDATACOPY"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALLDATACOPY
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
        // create expr by context
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());

        // create custom gate and lookup constraints
        let (src_type, _, src_offset, _, dest_type, _, dest_offset, _, len) =
            extract_lookup_expression!(copy, config.get_copy_lookup(meta));

        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + len.clone(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let mut stack_pop_values = vec![];
        for i in 0..3 {
            let state_entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                state_entry.clone(),
                i,
                NUM_ROW,
                (-1 * i as i32).expr(),
                false,
            ));
            let (_, _, value_hi, value_lo, ..) = extract_lookup_expression!(state, state_entry);
            stack_pop_values.push(value_lo);
            constraints.extend([(
                format!("CALLDATACOPY value_high_{} = 0", i).into(),
                value_hi.expr(),
            )])
        }
        let lenlo_inv = meta.query_advice(config.vers[24], Rotation::prev());
        let iszero_len =
            SimpleIsZero::new(&stack_pop_values[2], &lenlo_inv, String::from("length_lo"));

        constraints.extend([
            (
                "CALLDATACOPY opcode".into(),
                opcode - OpcodeId::CALLDATACOPY.as_u64().expr(),
            ),
            (
                "CALLDATACOPY next pc".into(),
                pc_next - pc_cur - PC_DELTA.expr(),
            ),
            (
                "CALLDATACOPY  dst_offset = stack top 0".into(),
                (1.expr() - iszero_len.expr()) * (stack_pop_values[0].expr() - dest_offset.expr()),
            ),
            (
                "CALLDATACOPY  src_offset = stack top 1".into(),
                (1.expr() - iszero_len.expr()) * (stack_pop_values[1].expr() - src_offset.expr()),
            ),
            (
                "CALLDATACOPY  length = stack top 2".into(),
                (1.expr() - iszero_len.expr()) * (stack_pop_values[2].expr() - len.expr()),
            ),
            (
                "CALLDATACOPY src_type is calldata".into(),
                (1.expr() - iszero_len.expr())
                    * (src_type.expr() - (copy::Type::Calldata as u8).expr()),
            ),
            (
                "CALLDATACOPY dst_type is memory".into(),
                (1.expr() - iszero_len.expr())
                    * (dest_type.expr() - (copy::Type::Memory as u8).expr()),
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
        let calldata_copy_lookup = query_expression(meta, |meta| config.get_copy_lookup(meta));

        vec![
            (
                "calldatacopy state lookup, stack top 0 dst_offset".into(),
                stack_lookup_0,
            ),
            (
                "calldatacopy state lookup, stack top 1 src_offset".into(),
                stack_lookup_1,
            ),
            (
                "calldatacopy state lookup, stack top2 length".into(),
                stack_lookup_2,
            ),
            ("calldatacopy lookup".into(), calldata_copy_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        // get three operand from stack
        let (dst_offset, dst_offset_value) = current_state.get_pop_stack_row_value(&trace);
        let (calldata_offset, calldata_offset_value) =
            current_state.get_pop_stack_row_value(&trace);
        let (length, length_value) = current_state.get_pop_stack_row_value(&trace);

        // get copydata and state from calldata
        let (copy_rows, mut state_rows) = current_state.get_calldata_copy_rows(
            dst_offset_value.as_usize(),
            calldata_offset_value.as_usize(),
            length_value.as_usize(),
        );

        // get three core circuit and fill content to them
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let copy_row: copy::Row;
        if length_value.is_zero() {
            copy_row = copy::Row {
                byte: 0.into(),
                src_type: copy::Type::Calldata,
                src_id: current_state.call_id.into(),
                src_pointer: calldata_offset_value,
                src_stamp: Some(current_state.state_stamp.into()),
                dst_type: copy::Type::Memory,
                dst_id: current_state.call_id.into(),
                dst_pointer: dst_offset_value,
                dst_stamp: current_state.state_stamp.into(),
                cnt: 0.into(),
                len: 0.into(),
            };
        } else {
            copy_row = copy_rows.get(0).unwrap().clone();
        }
        core_row_2.insert_copy_lookup(&copy_row);
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&dst_offset, &calldata_offset, &length]);
        let len_lo = F::from_u128(length_value.low_u128());
        let lenlo_inv =
            U256::from_little_endian(len_lo.invert().unwrap_or(F::ZERO).to_repr().as_ref());
        core_row_1.vers_24 = Some(lenlo_inv);

        let core_row_0 = ExecutionState::CALLDATACOPY.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        // generate witness for coredataload instruct
        state_rows.extend(vec![dst_offset, calldata_offset, length]);
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
    Box::new(CalldatacopyGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0x01.into(), 0x02.into(), 0x03.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_data: HashMap::new(),
            ..WitnessExecHelper::new()
        };
        current_state.call_data.insert(0, vec![0; 10]);
        let trace = prepare_trace_step!(0, OpcodeId::CALLDATACOPY, stack);
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
