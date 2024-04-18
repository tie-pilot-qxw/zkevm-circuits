use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{public, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep, U256};
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;

const PC_DELTA: u64 = 1;

/// CODESIZE overview:
///   get the bytecode size and put it on the top of the stack
///
/// CODESIZE Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 2 |       |       |       | PUBLIC(6)|
/// | 1 | STATE |       |       |          |
/// | 0 | DYNA_SELECTOR   | AUX |          |
/// +---+-------+-------+-------+----------+
pub struct CodesizeGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CodesizeGadget<F>
{
    fn name(&self) -> &'static str {
        "CODESIZE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CODESIZE
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
        let code_addr = meta.query_advice(config.code_addr, Rotation::cur());

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(STACK_POINTER_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(OpcodeId::CODESIZE.constant_gas_cost().expr()),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta.clone());
        constraints.extend(config.get_auxiliary_gas_constraints(meta, NUM_ROW, delta));

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // get stack val
        let stack_entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            stack_entry.clone(),
            0,
            NUM_ROW,
            1.expr(),
            true,
        ));
        let (_, _, stack_code_size_hi, stack_code_size_lo, _, _, _, _) =
            extract_lookup_expression!(state, stack_entry);

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
                "code address = (public_value[0] << 128) + public_values[1]".into(),
                public_values[0].clone() * pow_of_two::<F>(128) + public_values[1].clone()
                    - code_addr,
            ),
            (
                "stack_top hi(code_size hi) = public_values[2]".into(),
                stack_code_size_hi.clone() - public_values[2].clone(),
            ),
            (
                "stack_top lo(code_size lo) = public_values[2]".into(),
                stack_code_size_lo - public_values[3].clone(),
            ),
            ("code_size hi is zero".into(), stack_code_size_hi),
        ]);

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        vec![
            ("stack lookup".into(), stack_lookup),
            ("public lookup(code size)".into(), public_lookup),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert_eq!(trace.op, OpcodeId::CODESIZE);

        //  get the bytecode size and put it on the top of the stack
        let code_size = U256::from(
            current_state
                .bytecode
                .get(&current_state.code_addr)
                .unwrap()
                .code()
                .len(),
        );
        assert_eq!(current_state.stack_top.unwrap(), code_size);
        let push_row = current_state.get_push_stack_row(&trace, code_size);

        // get core row2
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        //  get public row and insert public row lookup
        let public_row = current_state.get_public_code_size_row(current_state.code_addr, code_size);
        core_row_2.insert_public_lookup(0, &public_row);

        // get core row1
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&push_row]);

        // get core row0
        let core_row_0 = ExecutionState::CODESIZE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![push_row],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CodesizeGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::constant::{GAS_LEFT_IDX, STACK_POINTER_IDX};
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
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + OpcodeId::CODESIZE.constant_gas_cost();

        let mut trace = prepare_trace_step!(0, OpcodeId::CODESIZE, stack);
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
                Some(U256::from(gas_left_before_exec));
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
    fn test_code_size_empty_code() {
        let stack = Stack::from_slice(&[]);
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let mut bytecode = HashMap::new();
        let code = Bytecode::from(Vec::new().to_vec());
        bytecode.insert(code_addr, code);
        let stack_top = U256::zero();
        run(stack, code_addr, bytecode, stack_top);
    }

    #[test]
    fn test_code_size() {
        // PUSH29 0x0000000000000000000000000000000000000000000000000000000000
        // POP
        // CODESIZE
        // result: 0x20
        let stack = Stack::from_slice(&[]);
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let mut bytecode = HashMap::new();
        // 32 byte
        let code = Bytecode::from(
            hex::decode("7c00000000000000000000000000000000000000000000000000000000005038")
                .unwrap(),
        );
        bytecode.insert(code_addr, code);
        let stack_top = U256::from(0x20);
        run(stack, code_addr, bytecode, stack_top);
    }
}
