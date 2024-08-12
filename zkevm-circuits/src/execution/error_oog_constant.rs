use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use crate::arithmetic_circuit::operation;
use crate::arithmetic_circuit::operation::get_lt_operations;
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_lt::SimpleLtGadget;
use gadgets::util::Expr;

use crate::execution::{
    end_call_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::{assign_or_panic, fixed, Witness, WitnessExecHelper};

/// Overview
///   Circuit constraints when insufficient gas fees occur for non-zero constant gas
///
/// Table Layout:
///     u64overflow: diff u64 constraint
///     lt, diff: gas_left < gas_cost
///     fixed_lookup: determine if it is a constant gas consumption.
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+
/// | cnt | 8 col             | 8col |                             8col                                      |
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+
/// | 1   | u64overflow (2..6)|      |      |         |          lt(26)|  diff(27)   | fixed_lookup (28..31) |
/// | 0   | DYNA_SELECTOR     |     AUX  |                                                                   |
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+

const NUM_ROW: usize = 2;
const LT_INDEX: usize = 26;
const DIFF_INDEX: usize = 27;
pub struct ErrorOOGConstantGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ErrorOOGConstantGadget<F>
{
    fn name(&self) -> &'static str {
        "ERROR_OOG_CONSTANT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ERROR_OOG_CONSTANT
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, end_call_1::NUM_ROW)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        let opcode = meta.query_advice(config.opcode, Rotation::cur());

        // 这里约束都是delta(0), 其中gas_left经过预处理，满足curr_step.gas_left = prev_step.gas_left
        let auxiliary_delta = AuxiliaryOutcome {
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        let (tag, [opcode_in_fixed, gas_cost, _]) =
            extract_lookup_expression!(fixed, config.get_fixed_lookup(meta, Rotation::prev()));

        constraints.extend([
            (
                "tag is ConstantGasCost".into(),
                tag - (fixed::Tag::ConstantGasCost as u8).expr(),
            ),
            ("opcode == opcode_in_fixed".into(), opcode - opcode_in_fixed),
        ]);

        let gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let lt = meta.query_advice(config.vers[LT_INDEX], Rotation::prev());
        let diff = meta.query_advice(config.vers[DIFF_INDEX], Rotation::prev());
        let is_lt = SimpleLtGadget::<F, 8>::new(&gas_left, &gas_cost, &lt, &diff);
        constraints.extend(is_lt.get_constraints());
        constraints.push(("gas_left < gas_cost".into(), 1.expr() - is_lt.expr()));

        let (tag, [diff_hi, diff_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        );
        let not_overflow = SimpleIsZero::new(&overflow, &overflow_inv, "diff not overflow".into());
        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            ("diff_hi == 0".into(), diff_hi.clone()),
            ("diff_lo = diff".into(), diff_lo - diff.clone()),
            ("diff not overflow".into(), 1.expr() - not_overflow.expr()),
        ]);
        constraints.append(&mut config.get_next_single_purpose_constraints(
            meta,
            CoreSinglePurposeOutcome {
                ..Default::default()
            },
        ));

        // 下一个状态是END_CALL_1
        constraints.extend(config.get_exec_state_constraints(
            meta,
            ExecStateTransition::new(
                vec![],
                NUM_ROW,
                vec![(ExecutionState::END_CALL_1, end_call_1::NUM_ROW, None)],
                None,
            ),
        ));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let u64_overflow_lookup = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 0, Rotation::prev())
        });
        let fixed_lookup =
            query_expression(meta, |meta| config.get_fixed_lookup(meta, Rotation::prev()));

        vec![
            (
                "error_oog_constant u64Overflow lookup".into(),
                u64_overflow_lookup,
            ),
            ("error_oog_constant fixed lookup".into(), fixed_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        current_state.return_success = false;
        let gas_cost = trace.gas_cost;

        // 这里的gas_left == trace.gas == current_state.gas_left == prev_step.gas_left,
        // 由于在上一个step中，是一个正确的步骤，此时gas_left已经被约束了u64
        let (lt, diff, ..) = get_lt_operations(
            &U256::from(current_state.gas_left),
            &U256::from(gas_cost),
            &U256::from(2).pow(U256::from(64)),
        );
        let (u64overflow_rows, ..) = operation::u64overflow::gen_witness::<F>(vec![diff]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        // 这里需要使用lookup的原因是为了保证此处opcode的gas_cost应该属于常量gas
        core_row_1.insert_fixed_lookup(
            fixed::Tag::ConstantGasCost,
            U256::from(trace.op.as_u8()),
            U256::from(trace.gas_cost),
            U256::zero(),
        );

        core_row_1.insert_arithmetic_tiny_lookup(0, &u64overflow_rows);
        assign_or_panic!(core_row_1[LT_INDEX], (lt as u8).into());
        assign_or_panic!(core_row_1[DIFF_INDEX], diff);

        let core_row_0 = ExecutionState::ERROR_OOG_CONSTANT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            arithmetic: u64overflow_rows,
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ErrorOOGConstantGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use eth_types::Bytecode;

    use crate::constant::GAS_LEFT_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };

    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, code_addr: U256, bytecode: HashMap<U256, Bytecode>) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            code_addr,
            bytecode,
            stack_pointer: stack.0.len(),
            gas_left: 0x1,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(
            0,
            OpcodeId::PUSH1,
            stack,
            Some(String::from("out of gas constant"))
        );
        trace.gas = current_state.gas_left;
        trace.gas_cost = OpcodeId::PUSH1.constant_gas_cost();

        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(current_state.gas_left.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_CALL_1.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.pc = trace.pc.into();
            row
        };
        let (witness, prover) =
            prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
        witness.print_csv();
        prover.assert_satisfied();
    }

    #[test]
    fn test_oog_constant() {
        // PUSH1(4)
        // PUSH1(5)
        // PUSH1(1)
        // STOP
        let stack = Stack::from_slice(&[4.into()]);
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let mut bytecode = HashMap::new();
        // 32 byte
        let code = Bytecode::from(hex::decode("60046005600100").unwrap());
        bytecode.insert(code_addr, code);
        run(stack, code_addr, bytecode);
    }
}
