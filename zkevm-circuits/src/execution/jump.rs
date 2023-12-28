use crate::execution::{
    AuxiliaryDelta, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::GethExecStep;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Overview
///   pop an element from the top of the stack as the target PC value to jump to，and the target PC must be JUMPDEST.
///   
/// Table Layout:
///    STATE: State lookup(stack_top0), src: Core circuit, target: State circuit table, 8 columns
///    BYTECODE: Bytecode lookup, make sure the target PC exists in Bytecode, src: Core circuit, target: Bytecode circuit table, 8 columns
/// +---+-------+-------+-------+------------+
/// |cnt| 8 col | 8 col | 8 col |   8col     |
/// +---+-------+-------+-------+------------+
/// | 1 | STATE |       |       |  BYTECODE |
/// | 0 | DYNA_SELECTOR   | AUX             |
/// +---+-------+-------+-------+-----------+

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = -1;

pub struct JumpGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for JumpGadget<F>
{
    fn name(&self) -> &'static str {
        "JUMP"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::JUMP
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
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());

        let auxiliary_delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        let state_entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            state_entry.clone(),
            0,
            NUM_ROW,
            0.expr(),
            false,
        ));

        let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, state_entry);

        // use CoreSinglePurposeOutcome gadget to constrain PC, Callid,tx_idx,code_addr
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::To(value_lo.clone()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        let (lookup_addr, expect_next_pc, _, not_code, _, _, _, _) =
            extract_lookup_expression!(bytecode, config.get_bytecode_full_lookup(meta));

        constraints.extend([
            (
                "opcode is JUMP".into(),
                opcode - OpcodeId::JUMP.as_u8().expr(),
            ),
            // because the target PC is a value in the u64 range, value_hi is 0
            ("stack top value_hi = 0".into(), value_hi - 0.expr()),
            (
                "bytecode lookup pc = stack top value_lo".into(),
                value_lo - expect_next_pc.clone(),
            ),
            (
                "bytecode lookup addr = code addr".into(),
                code_addr - lookup_addr,
            ),
            // target PC must be JUMPDEST, which is the opcode, not the byte of the push.
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
        let bytecode_loopup = query_expression(meta, |meta| config.get_bytecode_full_lookup(meta));
        vec![
            ("jump_lookup_stack".into(), stack_lookup),
            ("jump_lookup_bytecode".into(), bytecode_loopup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let (stack_pop_0, next_pc) = current_state.get_pop_stack_row_value(&trace);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_0]);

        core_row_1.insert_bytecode_full_lookup(
            next_pc.as_u64(),
            OpcodeId::JUMPDEST,
            core_row_1.code_addr,
            Some(0.into()),
        );

        let core_row_0 = ExecutionState::JUMP.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![stack_pop_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(JumpGadget {
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
        let jump_to_pc = 0x1;
        let stack = Stack::from_slice(&[jump_to_pc.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::JUMP, stack);
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
            row.pc = jump_to_pc.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied_par();
    }
}
