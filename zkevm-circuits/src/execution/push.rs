use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::WitnessExecHelper;
use crate::witness::{assign_or_panic, Witness};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;
/// opcode is push0 idx in row one  
const OPCODE_IS_PUSH0_IDX: usize = 8;
pub struct PushGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Push Execution State layout is as follows
/// where STATE means state table lookup,
/// BYTEFULL means byte table lookup (full mode),
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// where IP0(one column,idx is 8) means whether the opcode is PUSH0
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE |IP0    |       | BYTEFULL |
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
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let is_push0 = meta.query_advice(config.vers[OPCODE_IS_PUSH0_IDX], Rotation::prev());
        // PUSH1-PUSH32 gas cost is FASTEST,
        // PUSH0 gas cost is QUICK,
        let gas_cost = select::expr(
            is_push0.clone(),
            -OpcodeId::PUSH0.constant_gas_cost().expr(),
            -OpcodeId::PUSH1.constant_gas_cost().expr(),
        );
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
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
            (
                "opcode is one of push".into(),
                (1.expr() - is_push0.clone()) * (is_push.clone() - 1.expr()),
            ),
            (
                "value_hi = push_value".into(),
                push_value_hi - value_hi.clone(),
            ),
            (
                "value_lo = push_value".into(),
                push_value_lo - value_lo.clone(),
            ),
            ("bytecode lookup addr = code_addr".into(), code_addr - addr),
            ("bytecode lookup pc = pc".into(), pc_cur - pc),
            ("bytecode lookup not_code = 0".into(), not_code.clone()),
            // opcode is push0 constraint
            (
                "opcode is push0".into(),
                is_push0.clone() * (opcode.clone() - OpcodeId::PUSH0.expr()),
            ),
            // ispush0 is 0 or 1
            (
                "opcode is push0, is_push0 = 0 or 1".into(),
                is_push0.clone() * (is_push0.clone() - 1.expr()),
            ),
            // opcode is push0 ,then value_hi = 0 and value_lo = 0
            (
                "opcode is push0, value_hi = 0".into(),
                is_push0.clone() * (value_hi - 0.expr()),
            ),
            (
                "opcode is push0, value_lo = 0".into(),
                is_push0.clone() * (value_lo - 0.expr()),
            ),
        ]);
        let delta_core = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(cnt + 1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta_core));

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

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op.is_push());

        let stack_push = current_state.get_push_stack_row(trace, current_state.stack_top.unwrap());
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push]);
        core_row_1.insert_bytecode_full_lookup(
            trace.pc,
            trace.op,
            core_row_1.code_addr,
            current_state.stack_top,
        );
        let is_push0 = if trace.op == OpcodeId::PUSH0 {
            U256::one()
        } else {
            U256::zero()
        };
        assign_or_panic!(core_row_1[OPCODE_IS_PUSH0_IDX], is_push0);
        let core_row_0 = ExecutionState::PUSH.into_exec_state_core_row(
            trace,
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
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    #[test]
    fn assign_and_constraint() {
        // prepare a state to generate witness
        let stack = Stack::new();
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xcc.into()),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + OpcodeId::PUSH1.constant_gas_cost();
        let mut trace = prepare_trace_step!(0, OpcodeId::PUSH1, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] =
                Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = 2.into();
            row
        };
        let (_witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        prover.assert_satisfied();
    }
}
