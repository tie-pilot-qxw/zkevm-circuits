use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::util::expr_from_bytes;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::vec;

const NUM_ROW: usize = 3;
pub const LOAD_SIZE: usize = 32;
const STATE_STAMP_DELTA: usize = 34;
const PC_DELTA: usize = 1;
const STACK_POINTER_DELTA: usize = 0;
const HIGH_END_INDEX: usize = 16;

pub struct CalldataloadGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Calldataload read word from msg data at index idx in EVM,
/// idx in stack and will retrive data from msg.data[idx:idx+32] to stack.
/// data[idx]: 32-byte value starting from the given offset of the calldata.
/// All bytes after the end of the calldata are set to 0.
///
/// Calldataload Execution State layout is as follows
/// where STATE means state table lookup,
/// CONTENT means the bytes retrived from msg.data (calldata),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col  |
/// +---+-------+-------+-------+----------+
/// | 2 | CONTENT                          |
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
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                STACK_POINTER_DELTA.expr(),
                i == 1,
            ));
        }

        let push_entry = config.get_state_lookup(meta, 1);
        let (_, stamp, value_hi, value_lo, _, _, _, _) =
            extract_lookup_expression!(state, push_entry.clone());
        let calldata_high_value: Vec<Expression<F>> = config.vers[..HIGH_END_INDEX]
            .iter()
            .map(|s| meta.query_advice(*s, Rotation(-2)))
            .collect();
        let calldata_low_value: Vec<Expression<F>> = config.vers[HIGH_END_INDEX..]
            .iter()
            .map(|s| meta.query_advice(*s, Rotation(-2)))
            .collect();
        constraints.extend([
            (
                "CALLDATALOAD opcode".into(),
                opcode - OpcodeId::CALLDATALOAD.as_u8().expr(),
            ),
            (
                "CALLDATALOAD next pc".into(),
                pc_next - pc_cur - PC_DELTA.expr(),
            ),
            (
                "CALLDATALOAD call data high value".into(),
                value_hi - expr_from_bytes(calldata_high_value.as_slice()),
            ),
            (
                "CALLDATALOAD call data low value".into(),
                value_lo - expr_from_bytes(calldata_low_value.as_slice()),
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
        let (_, stamp, _, _, _, _, pointer, _) =
            extract_lookup_expression!(state, stack_push.clone());
        let mut calldata_load: Vec<(String, LookupEntry<F>)> = vec![];
        for i in 0..LOAD_SIZE {
            calldata_load.push((
                format!("content with index{} in calldata", i),
                query_expression(meta, |meta| {
                    config.get_calldata_load_lookup(
                        meta,
                        i,
                        pointer.clone(),
                        stamp.clone(),
                        &config.vers[i],
                    )
                }),
            ))
        }
        calldata_load.extend([
            ("stack pop index".into(), stack_pop),
            ("stack push call_data".into(), stack_push),
        ]);
        calldata_load
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CALLDATALOAD);

        // pop index from stack to point msg.call_data
        let (stack_pop_0, index) = current_state.get_pop_stack_row_value(trace);
        // load value from msg.call_data with index
        let call_data = &current_state.call_data[&current_state.call_id];
        let len = if index.as_usize() + LOAD_SIZE <= call_data.len() {
            index.as_usize() + LOAD_SIZE
        } else {
            call_data.len()
        };
        let mut data: Vec<u8> = vec![];
        data.extend(&call_data[index.as_usize()..len]);
        data.resize(LOAD_SIZE, 0);

        // then push the retrived value to stack
        let stack_push_0 = current_state.get_push_stack_row(trace, U256::from(&data[0..]));
        let mut state_rows: Vec<state::Row> =
            current_state.get_calldata_load_rows(index.as_usize(), LOAD_SIZE);
        // generate Witness with call_data
        let mut core_row_2 = current_state.get_core_row_without_versatile(trace, 2);
        let values = data.into_iter().map(|x| x.into()).collect::<Vec<U256>>();
        core_row_2.fill_versatile_with_values(&values);
        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);
        let core_row_0 = ExecutionState::CALLDATALOAD.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        let mut v: Vec<state::Row> = vec![stack_pop_0, stack_push_0];
        v.append(&mut state_rows);
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: v,
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
    use std::collections::HashMap;

    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            call_data: HashMap::new(),
            ..WitnessExecHelper::new()
        };
        current_state.call_data.insert(0, vec![0, 32]);
        let trace = prepare_trace_step!(0, OpcodeId::CALLDATALOAD, stack);
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
