use crate::execution::{
    Auxiliary, AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{copy, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::CoreSinglePurposeOutcome;

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
        // create custom gate and lookup constraints
        let (_, _, _, _, _, _, _, _, len) =
            extract_lookup_expression!(copy, config.get_copy_lookup(meta));
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr() + len.clone(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));
        constraints.append(&mut config.get_copy_contraints(
            "CALLDATACOPY".to_string(),
            meta,
            OpcodeId::CALLDATACOPY,
            PC_DELTA,
            copy::Type::Calldata,
            copy::Type::Memory,
            NUM_ROW,
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
                src_type: copy::Type::default(),
                src_id: 0.into(),
                src_pointer: 0.into(),
                src_stamp: None, //Some(0.into()),
                dst_type: copy::Type::default(),
                dst_id: 0.into(),
                dst_pointer: 0.into(),
                dst_stamp: 0.into(),
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
    use std::fs::File;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn copylength_less_or_equal_calldata() {
        //[length, src_offset, dst_offset]
        let stack = Stack::from_slice(&[0x01.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        assign_and_constraint(stack, current_state, "copylength_le_calldata")
    }

    #[test]
    fn copylength_great_calldata() {
        let stack = Stack::from_slice(&[0x20.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        assign_and_constraint(stack, current_state, "copylength_gt_calldata");
    }

    #[test]
    fn copylength_equal_0() {
        let stack = Stack::from_slice(&[0x00.into(), 0x02.into(), 0x03.into()]);

        let mut current_state = WitnessExecHelper {
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        current_state.stack_pointer = stack.0.len();
        current_state.call_data.insert(0, vec![0; 10]);

        assign_and_constraint(stack, current_state, "copylength_eq_0");
    }

    // #[test]
    fn assign_and_constraint(stack: Stack, mut current_state: WitnessExecHelper, file_name: &str) {
        let stack_pointer = stack.0.len();
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
        // let mut buf =
        //     std::io::BufWriter::new(File::create(format!("test_data/{}.html", file_name)).unwrap());
        // witness.write_html(&mut buf);
    }
}
