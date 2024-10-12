use std::marker::PhantomData;

use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;

use crate::execution::{
    end_call_1, AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecStateTransition, ExecutionConfig,
    ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::query_expression;
use crate::witness::{fixed, Witness, WitnessExecHelper};

/// Overview
///   Circuit constraints when an invalid opcode is encountered.
///
/// Table Layout:
///     fixed_lookup: check whether opcode is invalid.
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+
/// | cnt | 8 col             | 8col |                             8col                                      |
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+
/// | 1   | fixed_lookup (2..5)|      |      |         |          |           |                              |
/// | 0   | DYNA_SELECTOR     |     AUX  |                                                                   |
/// +-----+-------------------+------+------+---------+------------------+-----------------------+-----------+

const NUM_ROW: usize = 2;
pub struct ErrorInvalidOpcodeGadget<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ErrorInvalidOpcodeGadget<F>
{
    fn name(&self) -> &'static str {
        "ERROR_INVALID_OPCODE"
    }

    fn execution_state(&self) -> ExecutionState {
        ExecutionState::ERROR_INVALID_OPCODE
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

        let auxiliary_delta = AuxiliaryOutcome::default();

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);

        let (tag, [opcode_in_fixed, _, _]) =
            extract_lookup_expression!(fixed, config.get_fixed_lookup(meta, Rotation::prev()));

        //  约束tag和当前的opcode
        constraints.extend([
            (
                "tag is IsInvalidOpcode".into(),
                tag - (fixed::Tag::IsInvalidOpcode as u8).expr(),
            ),
            ("opcode == opcode_in_fixed".into(), opcode - opcode_in_fixed),
        ]);

        constraints.append(
            &mut config
                .get_next_single_purpose_constraints(meta, CoreSinglePurposeOutcome::default()),
        );

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
        let fixed_lookup =
            query_expression(meta, |meta| config.get_fixed_lookup(meta, Rotation::prev()));

        vec![("error_invalid_opcode fixed lookup".into(), fixed_lookup)]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        current_state.return_success = false;
        let opcode = trace.op.as_u8();
        assert!(
            OpcodeId::invalid_opcodes().contains(&OpcodeId::from(opcode)),
            "Invalid opcode encountered"
        );
        let is_invalid_flag = 1u8;

        let mut core_row_1 = current_state.get_core_row_without_versatile(trace, 1);
        core_row_1.insert_fixed_lookup(
            fixed::Tag::IsInvalidOpcode,
            U256::from(opcode),
            U256::from(is_invalid_flag),
            U256::zero(),
        );

        let core_row_0 = ExecutionState::ERROR_INVALID_OPCODE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_1, core_row_0],
            ..Default::default()
        }
    }
}

pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ErrorInvalidOpcodeGadget {
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::constant::GAS_LEFT_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use eth_types::Bytecode;

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
            OpcodeId::INVALID(0xfe),
            stack,
            Some(String::from("invalid opcode"))
        );
        trace.gas = current_state.gas_left;
        trace.gas_cost = 0;

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
    fn test_invalid_opcode() {
        let stack = Stack::from_slice(&[4.into()]);
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let mut bytecode = HashMap::new();
        // PUSH1 0x1 INVALID (0xfe) STOP
        let code = Bytecode::from(hex::decode("600160010bfe00").unwrap());
        bytecode.insert(code_addr, code);
        run(stack, code_addr, bytecode);
    }
}
