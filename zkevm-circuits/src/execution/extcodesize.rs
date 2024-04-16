use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{public, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 2;

const PC_DELTA: u64 = 1;

/// EXTCODESIZE overview:
///   pop a value from the top of the stack: address, get the corresponding codesize according to the address,
/// and write the codesize to the top of the stack
///
/// EXTCODESIZE Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 2 |       |       |       | PUBLIC(6)|
/// | 1 | STATE | STATE |       |          |
/// | 0 | DYNA_SELECTOR   | AUX |          |
/// +---+-------+-------+-------+----------+
pub struct ExtcodesizeGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for ExtcodesizeGadget<F>
{
    fn name(&self) -> &'static str {
        "EXTCODESIZE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::EXTCODESIZE
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
        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // get stack val
        let mut stack_operands = vec![];
        for i in 0..2 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                0.expr(),
                i == 1,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            stack_operands.push([value_hi, value_lo]);
        }

        // get public val
        // public_values[0] is code address hi
        // public_values[1] is code address lo
        // public_values[2] is code size hi (must be zero, because of the rigid requirements of EVM (the code size does not exceed about 40,000))
        // public_values[3] is code size lo
        let public_entry = config.get_public_lookup(meta, 0);
        let (public_tag, _, public_values) = extract_lookup_expression!(public, public_entry);

        constraints.extend([
            (
                "public tag is CodeSize".into(),
                public_tag - (public::Tag::CodeSize as u8).expr(),
            ),
            (
                "stack_top hi(code address hi) = public_value[0] ".into(),
                stack_operands[0][0].clone() - public_values[0].clone(),
            ),
            (
                "stack_top lo(code address lo) = public_value[1] ".into(),
                stack_operands[0][1].clone() - public_values[1].clone(),
            ),
            (
                "stack_push hi(code_size hi) = public_values[2]".into(),
                stack_operands[1][0].clone() - public_values[2].clone(),
            ),
            (
                "stack_push lo(code_size lo) = public_values[2]".into(),
                stack_operands[1][1].clone() - public_values[3].clone(),
            ),
            ("code_size hi is zero".into(), stack_operands[1][0].clone()),
        ]);

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_addr = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_code_size =
            query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stack addr lookup".into(), stack_lookup_addr),
            ("stack code size lookup".into(), stack_lookup_code_size),
            ("public lookup(code size)".into(), public_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::EXTCODESIZE);

        let (stack_pop_addr, code_address) = current_state.get_pop_stack_row_value(&trace);

        //  get the bytecode size and put it on the top of the stack
        let code_size = U256::from(
            current_state
                .bytecode
                .get(&code_address)
                .unwrap()
                .code()
                .len(),
        );
        assert_eq!(current_state.stack_top.unwrap(), code_size);
        let stack_push_row = current_state.get_push_stack_row(&trace, code_size);

        // get core row2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        //  get public row and insert public row lookup
        let public_row = current_state.get_public_code_size_row(code_address, code_size);
        core_row_2.insert_public_lookup(0, &public_row);

        // get core row1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_addr, &stack_push_row]);

        // get core row0
        let core_row_0 = ExecutionState::EXTCODESIZE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_addr, stack_push_row],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(ExtcodesizeGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::STACK_POINTER_IDX;
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    use eth_types::Bytecode;
    use std::collections::HashMap;
    generate_execution_gadget_test_circuit!();

    fn run(stack: Stack, code_addr: U256, bytecode: HashMap<U256, Bytecode>, stack_top: U256) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            code_addr,
            bytecode,
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::EXTCODESIZE, stack);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
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
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_code_size1() {
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let stack = Stack::from_slice(&[code_addr]);
        let mut bytecode = HashMap::new();
        let code = Bytecode::from(Vec::new().to_vec());
        bytecode.insert(code_addr, code);
        let stack_top = U256::zero();
        run(stack, code_addr, bytecode, stack_top);
    }

    #[test]
    fn test_code_size2() {
        // PUSH29 0x0000000000000000000000000000000000000000000000000000000000
        // POP
        // CODESIZE
        // result: 0x20
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let stack = Stack::from_slice(&[code_addr]);
        let mut bytecode = HashMap::new();
        let code = Bytecode::from(
            hex::decode("7c00000000000000000000000000000000000000000000000000000000005038")
                .unwrap(),
        );
        bytecode.insert(code_addr, code);
        // 32 byte
        let stack_top = U256::from(0x20);
        run(stack, code_addr, bytecode, stack_top);
    }
}
