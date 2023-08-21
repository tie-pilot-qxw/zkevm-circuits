use crate::execution::{Auxiliary, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::extract_enum_value;
use crate::table::LookupEntry;
use crate::util::query_expression;
use crate::witness::{arithmetic, CurrentState};
use crate::witness::{core, state, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i64 = -1;
const PC_DELTA: u64 = 1;

pub struct AddGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Add Execution State layout is as follows
/// where STATE means state table lookup,
/// ARITH means arithmetic table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | ARITH  |      |       |          |
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for AddGadget<F>
{
    fn name(&self) -> &'static str {
        "ADD"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ADD
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
        let call_id = meta.query_advice(config.call_id, Rotation::cur());
        let Auxiliary {
            state_stamp,
            stack_pointer,
            log_stamp,
            gas_left,
            refund,
            memory_chunk,
            read_only,
            ..
        } = config.get_auxiliary();
        let state_stamp_cur = meta.query_advice(state_stamp, Rotation::cur());
        let state_stamp_prev = meta.query_advice(state_stamp, Rotation(-1 * NUM_ROW as i32));
        let stack_pointer_cur = meta.query_advice(stack_pointer, Rotation::cur());
        let stack_pointer_prev = meta.query_advice(stack_pointer, Rotation(-1 * NUM_ROW as i32));
        let log_stamp_cur = meta.query_advice(log_stamp, Rotation::cur());
        let log_stamp_prev = meta.query_advice(log_stamp, Rotation(-1 * NUM_ROW as i32));
        let read_only_cur = meta.query_advice(read_only, Rotation::cur());
        let read_only_prev = meta.query_advice(read_only, Rotation(-1 * NUM_ROW as i32));
        let mut constraints = vec![];
        let mut arithmetic_operands = vec![];
        for i in 0..3 {
            let (tag, stamp, value_hi, value_lo, call_id_contract_addr, _, pointer_lo, is_write) = extract_enum_value!(
                config.get_state_lookup(meta,  i), LookupEntry::State { tag, stamp, value_hi, value_lo, call_id_contract_addr, pointer_hi, pointer_lo, is_write} =>
                (tag, stamp, value_hi, value_lo, call_id_contract_addr, pointer_hi, pointer_lo, is_write));
            constraints.extend_from_slice(&[
                (
                    "state lookup tag = stack".into(),
                    tag - (state::Tag::Stack as u8).expr(),
                ),
                (
                    format!("state stamp for state lookup[{}]", i),
                    stamp - state_stamp_prev.clone() - i.expr(),
                ),
                (
                    "state lookup call id".into(),
                    call_id_contract_addr - call_id.clone(),
                ),
                (
                    "pointer_lo".into(),
                    if i != 0 {
                        pointer_lo - stack_pointer_cur.clone()
                    } else {
                        pointer_lo - stack_pointer_cur.clone() - 1.expr() // first stack operand has +1 pointer
                    },
                ),
                (
                    "is_write".into(),
                    if i != 2 {
                        is_write // first and second stack are read
                    } else {
                        is_write - 1.expr() // third stack is write
                    },
                ),
            ]);
            arithmetic_operands.extend_from_slice(&[value_hi, value_lo]);
        }
        let (tag, arithmetic_operands_full) = extract_enum_value!(
            config.get_arithmetic_lookup(meta), LookupEntry::Arithmetic { tag, values } => (tag, values));
        // iterate over three operands (0..6), since we don't need constraint on the fourth
        constraints.extend((0..6).map(|i| {
            (
                format!("operand[{}] in arithmetic = in state lookup", i),
                arithmetic_operands[i].clone() - arithmetic_operands_full[i].clone(),
            )
        }));
        constraints.extend_from_slice(&[
            ("opcode".into(), opcode - OpcodeId::ADD.as_u8().expr()),
            ("next pc".into(), pc_next - pc_cur - PC_DELTA.expr()),
            (
                "state stamp".into(),
                state_stamp_cur - state_stamp_prev - STATE_STAMP_DELTA.expr(),
            ),
            (
                "stack pointer".into(),
                if STACK_POINTER_DELTA >= 0 {
                    stack_pointer_cur - stack_pointer_prev - (STACK_POINTER_DELTA as u64).expr()
                } else {
                    stack_pointer_cur - stack_pointer_prev + (-STACK_POINTER_DELTA as u64).expr()
                },
            ),
            ("log stamp".into(), log_stamp_cur - log_stamp_prev),
            ("read only".into(), read_only_cur - read_only_prev),
            (
                "arithmetic tag".into(),
                tag - (arithmetic::Tag::Add as u8).expr(),
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
        let arithmetic = query_expression(meta, |meta| config.get_arithmetic_lookup(meta));
        vec![
            ("stack pop b".into(), stack_lookup_0),
            ("stack pop a".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
            ("arithmetic lookup".into(), arithmetic),
        ]
    }

    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert_eq!(trace.op, OpcodeId::ADD);

        let (stack_pop_a, a) = current_state.get_pop_stack_row_value();
        let (stack_pop_b, b) = current_state.get_pop_stack_row_value();
        // todo another carry_lo ?
        let (c, carry_hi) = a.overflowing_add(b);
        let stack_push_c = current_state.get_push_stack_row(c);
        let mut d = (carry_hi as u128).into();
        d <<= 128; // todo check this line
        let arithmetic_rows = Witness::gen_arithmetic_witness(arithmetic::Tag::Add, [a, b, c, d]);
        let mut core_row_2 = current_state.get_core_row_without_versatile(2);
        core_row_2.insert_arithmetic_lookup(&arithmetic_rows[0]);
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_pop_a, &stack_pop_b, &stack_push_c]);
        let core_row_0 = ExecutionState::ADD.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            bytecode: vec![],
            copy: vec![],
            core: vec![core_row_2, core_row_1, core_row_0],
            exp: vec![],
            public: vec![],
            state: vec![stack_pop_b, stack_pop_a, stack_push_c],
            arithmetic: arithmetic_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(AddGadget {
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
        let stack = Stack::from_slice(&[1.into(), 2.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };
        // prepare a trace
        let trace = Trace {
            pc: 0,
            op: OpcodeId::ADD,
            push_value: None,
        };
        current_state.copy_from_trace(&trace);
        let mut padding_begin_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_begin_row.vers_21 = Some(stack_pointer.into());
        let mut padding_end_row = ExecutionState::END_BLOCK.into_exec_state_core_row(
            &mut current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        padding_end_row.pc = 1.into();
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
