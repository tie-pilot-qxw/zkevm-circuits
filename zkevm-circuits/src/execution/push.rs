use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::CurrentState;
use crate::witness::{core, state, Witness};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;

pub struct PushGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Push Execution State layout is as follows
/// where STATE means state table lookup,
/// BYTEFULL means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE |       |       | BYTEFULL |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PushGadget<F>
{
    fn name(&self) -> &'static str {
        "PUSH"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::PUSH
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
        let pc_cur = meta.query_advice(config.pc, Rotation::cur());
        let pc_next = meta.query_advice(config.pc, Rotation::next());
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let state_entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            state_entry.clone(),
            0,
            NUM_ROW,
            1.expr(),
            true,
        ));
        let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, state_entry);
        let (addr, pc, _, not_code, push_value_hi, push_value_lo, cnt, is_push) =
            extract_lookup_expression!(bytecode, config.get_bytecode_full_lookup(meta));
        constraints.extend([
            ("opcode is one of push".into(), is_push - 1.expr()),
            ("next pc".into(), pc_next - pc_cur.clone() - cnt - 1.expr()),
            ("value_hi = push_value".into(), push_value_hi - value_hi),
            ("value_lo = push_value".into(), push_value_lo - value_lo),
            ("bytecode lookup addr = code_addr".into(), code_addr - addr),
            ("bytecode lookup pc = pc".into(), pc_cur - pc),
            ("bytecode lookup not_code = 0".into(), not_code),
        ]);
        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let bytecode_lookup = query_expression(meta, |meta| config.get_bytecode_full_lookup(meta));
        vec![
            ("push_lookup_stack".into(), stack_lookup),
            ("push_lookup_bytecode_full".into(), bytecode_lookup),
        ]
    }

    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert!(trace.op.is_push());

        let stack_push = current_state.get_push_stack_row(trace.push_value.unwrap());
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_push]);
        core_row_1.insert_bytecode_full_lookup(
            current_state.pc,
            current_state.opcode,
            trace.push_value,
        );
        let core_row_0 = ExecutionState::PUSH.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row_1, core_row_0],
            exp: vec![],
            public: vec![],
            state: vec![stack_push],
            arithmetic: vec![],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(PushGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };
        // prepare a trace
        let trace = Trace {
            pc: 0,
            op: OpcodeId::PUSH1,
            push_value: Some(0xcc.into()),
        };
        current_state.copy_from_trace(&trace);
        let mut padding_begin_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_begin_row.vers_21 = Some(stack_pointer.into());
        let mut padding_end_row = ExecutionState::END_PADDING.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_end_row.pc = 2.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied_par();
    }
}
