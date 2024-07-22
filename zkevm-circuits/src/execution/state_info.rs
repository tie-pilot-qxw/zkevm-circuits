use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
const PC_DELTA: u64 = 1;
const TAG_IDX: usize = 9;

/// StateInfo gadget:
/// The MSIZE opcode returns the size of the memory in bytes.
/// The PC opcode returns the current value of the program counter.
/// The memory is always fully accessible. What this instruction tracks is the highest
/// offset that was accessed in the current execution.
/// The TAG is used to select between the two opcodes.
///  A first write or read to a bigger offset will trigger a memory expansion,
/// which will cost gas. The size is always a multiple of a word (32 bytes).
/// STATE: State lookup (stack_pop), src: Core circuit, target: State circuit table, 8 columns
///
/// +---+-------+--------+--------+----------+
/// |cnt| 8 col | 8 col  | 8 col  | 8 col    |
/// +---+-------+--------+--------+----------+
/// | 1 | STATE | TAG |                      |
/// | 0 | DYNA_SELECTOR         | AUX        |
/// +---+-------+--------+--------+----------+

pub struct StateInfoGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for StateInfoGadget<F>
{
    fn name(&self) -> &'static str {
        "STATE_INFO"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STATE_INFO
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
        let mut constraints = vec![];

        // get tag
        let msize_tag = meta.query_advice(config.vers[TAG_IDX], Rotation::prev());
        let pc_tag = meta.query_advice(config.vers[TAG_IDX + 1], Rotation::prev());

        // Create a simple selector with tag
        let selector = SimpleSelector::new(&[msize_tag.clone(), pc_tag.clone()]);
        // Add constraints for the selector.
        constraints.extend(selector.get_constraints());

        // Add constraints for opcode.
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.push((
            "opcode".into(),
            opcode
                - selector.select(&[OpcodeId::MSIZE.as_u8().expr(), OpcodeId::PC.as_u8().expr()]),
        ));

        // Get the gas cost for the opcode.
        let gas_cost = selector.select(&[
            OpcodeId::MSIZE.constant_gas_cost().expr(),
            OpcodeId::PC.constant_gas_cost().expr(),
        ]);

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            memory_chunk: ExpressionOutcome::Delta(0.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        // Get the auxiliary constraints.
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        // Get the core single-purpose constraints.
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // get state lookup
        let state_entry = config.get_state_lookup(meta, 0);

        // Get the stack constraints.
        constraints.append(&mut config.get_stack_constraints(
            meta,
            state_entry.clone(),
            0,
            NUM_ROW,
            STACK_POINTER_DELTA.expr(),
            true,
        ));
        // Extract the value_hi and value_lo from the state lookup expression.
        let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, state_entry);

        // get state info
        let memory_chunk = meta.query_advice(config.get_auxiliary().memory_chunk, Rotation::cur());
        let pc = meta.query_advice(config.pc, Rotation::cur());

        // constrain value hi must be 0
        constraints.push(("value hi must be 0".into(), value_hi.clone()));

        // constrain value lo equal to memory_chunk or pc
        constraints.push((
            "value lo equal to memory_chunk or pc".into(),
            value_lo.clone() - selector.select(&[memory_chunk.clone() * 32.expr(), pc.clone()]),
        ));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        vec![("stack push".into(), stack_lookup)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::MSIZE || trace.op == OpcodeId::PC);

        let push_value = match trace.op {
            // get memory size from trace
            OpcodeId::MSIZE => trace.memory.0.len().into(),
            // get pc from trace
            OpcodeId::PC => trace.pc.into(),
            _ => unreachable!(),
        };
        let stack_push = current_state.get_push_stack_row(trace, push_value);

        // coew row 1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push]);
        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [TAG_IDX, TAG_IDX + 1],
            match trace.op {
                OpcodeId::MSIZE => 0,
                OpcodeId::PC => 1,
                _ => panic!(),
            },
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        // core row 0
        let core_row_0 = ExecutionState::STATE_INFO.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_push],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(StateInfoGadget {
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
    #[test]
    fn assign_and_constraint_msize() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 32];
        let value = U256::from_big_endian(&value_vec);
        let init_gas = 0x254023u64;
        let gas_left_before_exec = init_gas + OpcodeId::MSIZE.constant_gas_cost();

        let mut trace = prepare_trace_step!(0, OpcodeId::MSIZE, stack.clone());
        trace.gas = gas_left_before_exec;
        trace.memory.0 = vec![0; 0x10020];
        for i in 0..32 {
            trace.memory.0.insert(0xffff + i, value_vec[i]);
        }

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(value),
            memory_chunk: ((trace.memory.0.len() + 1) / 32) as u64,
            memory_chunk_prev: ((trace.memory.0.len() + 1) / 32) as u64,
            gas_left: init_gas,
            ..WitnessExecHelper::new()
        };

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
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
        prover.assert_satisfied();
    }

    #[test]
    fn assign_and_constraint_pc() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let value_vec = [0x12; 32];
        let value = U256::from_big_endian(&value_vec);
        let init_gas = 0x254023u64;
        let gas_left_before_exec = init_gas + OpcodeId::PC.constant_gas_cost();

        let mut trace = prepare_trace_step!(0, OpcodeId::PC, stack.clone());
        trace.gas = gas_left_before_exec;
        trace.pc = 64;

        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(value),
            gas_left: init_gas,
            ..WitnessExecHelper::new()
        };

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row.pc = 64.into();
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 65.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn assign_and_constraint_len_0() {
        let value = U256::from_big_endian(&[0x12; 32]);
        let stack = Stack::from_slice(&[value, 0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        // 2.确认流程中改状态可能需要的gas消耗，例如这里的834，计算出前一个状态的值
        let gas_left_before_exec = current_state.gas_left + OpcodeId::MSIZE.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, OpcodeId::MSIZE, stack);
        trace.gas = gas_left_before_exec;

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
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
        prover.assert_satisfied();
    }
}
