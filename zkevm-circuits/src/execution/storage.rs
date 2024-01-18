use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{state, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, GethExecStep};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 2;

const STATE_STAMP_DELTA: u64 = 4;
const STACK_POINTER_DELTA_SLOAD: i32 = 0;
const STACK_POINTER_DELTA_SSTORE: i32 = -2;
const PC_DELTA: u64 = 1;

/// Storage is a combination of Sload and Sstore.
/// Algorithm overview:
/// SLOAD:
///     1. get key from stack
///     2. get value = storage[key]
///     3. write value to stack
/// SSTORE:
///     1. get key and value from stack
///     2. write value to storage[key]
/// Table layout:
/// SLOAD:
///     STATE1:  State lookup(call_context read storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack pop key), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  State lookup(storage read value), src: Core circuit, target: State circuit table, 8 columns
///     STATE4:  stack lookup(stack push value), src: Core circuit, target: State circuit table, 8 columns
/// SSTORE:
///     STATE1:  State lookup(call_context read storage_contract_addr), src: Core circuit, target: State circuit table, 8 columns
///     STATE2:  State lookup(stack pop key), src: Core circuit, target: State circuit table, 8 columns
///     STATE3:  State lookup(stack pop value), src: Core circuit, target: State circuit table, 8 columns
///     STATE4:  stack lookup(storage write value), src: Core circuit, target: State circuit table, 8 columns
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | 8 col    |
/// +---+-------+-------+-------+----------+
/// | 1 | STATE1| STATE2| STATE3| STATE4   |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
///
/// Note:
///     1. In STATE3 of SLOAD and STATE4 of SSTORE, contract_addr is value hi,lo of STATE1 and pointer hi,lo is value hi,lo of STATE2.
///     2. STATE4's value hi,lo equals to value hi,lo of STATE3
pub struct StorageGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for StorageGadget<F>
{
    fn name(&self) -> &'static str {
        "STORAGE"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::STORAGE
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
        // append auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            stack_pointer: ExpressionOutcome::Delta(
                STACK_POINTER_DELTA_SLOAD.expr()
                    * (OpcodeId::SSTORE.as_u8().expr() - opcode.clone())
                    + STACK_POINTER_DELTA_SSTORE.expr()
                        * (opcode.clone() - OpcodeId::SLOAD.as_u8().expr()),
            ), //the property OpcodeId::SSTORE - OpcodeId::SLOAD == 1 is used
            ..Default::default()
        };

        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        // append stack constraints, call_context constraints and storage constrains
        let mut operands: Vec<[Expression<F>; 2]> = vec![];
        for i in 0..4 {
            let entry = config.get_state_lookup(meta, i);

            if i == 0 {
                let call_id = meta.query_advice(config.call_id, Rotation::cur());
                constraints.append(&mut config.get_call_context_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    false,
                    (state::CallContextTag::StorageContractAddr as u8).expr(),
                    call_id,
                ));
            } else if i == 1 {
                constraints.append(&mut config.get_stack_constraints(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    0.expr(),
                    false,
                ));
            } else {
                constraints.append(&mut config.get_storage_constraints_with_selector(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    operands[0][0].clone(),
                    operands[0][1].clone(),
                    operands[1][0].clone(),
                    operands[1][1].clone(),
                    if i == 2 { false } else { true },
                    if i == 2 {
                        OpcodeId::SSTORE.as_u8().expr() - opcode.clone()
                    } else {
                        opcode.clone() - OpcodeId::SLOAD.as_u8().expr()
                    }, //enable the constraints when i == 2, opcode == SLOAD or i == 3, opcode == SSTORE
                ));
                constraints.append(&mut config.get_stack_constraints_with_selector(
                    meta,
                    entry.clone(),
                    i,
                    NUM_ROW,
                    if i == 2 { (-1).expr() } else { 0.expr() },
                    if i == 2 { false } else { true },
                    if i == 2 {
                        opcode.clone() - OpcodeId::SLOAD.as_u8().expr()
                    } else {
                        OpcodeId::SSTORE.as_u8().expr() - opcode.clone()
                    }, //enable the constraints when i == 2, opcode == SSTORE or i == 3, opcode == SLOAD
                ));
            }
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.push([value_hi, value_lo]);
        }

        let storage_read_stack_pop = operands[2].clone();
        let stack_push_storage_write = operands[3].clone();
        // append constraints for state_lookup's values
        constraints.extend([
            (
                "storage_read == stack_push or stack_pop == storage_write hi".into(),
                storage_read_stack_pop[0].clone() - stack_push_storage_write[0].clone(),
            ),
            (
                "storage_read == stack_push or stack_pop == storage_write lo".into(),
                storage_read_stack_pop[1].clone() - stack_push_storage_write[1].clone(),
            ),
        ]);
        // append opcode constraint
        constraints.extend([(
            "opcode".into(),
            (opcode.clone() - OpcodeId::SLOAD.expr()) * (opcode - OpcodeId::SSTORE.expr()),
        )]);
        // append core single purpose constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));

        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let storage_contract_addr_lookup =
            query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let storage_or_stack_lookup_0 =
            query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let storage_or_stack_lookup_1 =
            query_expression(meta, |meta| config.get_state_lookup(meta, 3));
        vec![
            ("StorageContractAddr".into(), storage_contract_addr_lookup),
            ("stack pop".into(), stack_lookup),
            (
                "storage read or stack pop".into(),
                storage_or_stack_lookup_0,
            ),
            (
                "stack push or storage write".into(),
                storage_or_stack_lookup_1,
            ),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::SLOAD || trace.op == OpcodeId::SSTORE);
        //generate storage_contract_addr read row
        let (storage_contract_addr_row, storage_contract_addr) =
            current_state.get_storage_contract_addr_row();
        //generate storage pop key row
        let (stack_pop_row, storage_key) = current_state.get_pop_stack_row_value(&trace);
        //generate storage read row and stack push value row (for SLOAD) or stack pop value row and storage write row (for SSTORE)
        let (storage_or_stack_0, storage_or_stack_1) = if trace.op == OpcodeId::SLOAD {
            let (storage_or_stack_0, value) = current_state.get_storage_read_row_value(
                &trace,
                storage_key,
                storage_contract_addr,
            );
            let storage_or_stack_1 = current_state.get_push_stack_row(&trace, value);
            (storage_or_stack_0, storage_or_stack_1)
        } else {
            let (storage_or_stack_0, value) = current_state.get_pop_stack_row_value(&trace);
            let storage_or_stack_1 =
                current_state.get_storage_write_row(storage_key, value, storage_contract_addr);
            (storage_or_stack_0, storage_or_stack_1)
        };
        //generate core rows
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        // insert lookUp: Core ---> State
        core_row_1.insert_state_lookups([
            &storage_contract_addr_row,
            &stack_pop_row,
            &storage_or_stack_0,
            &storage_or_stack_1,
        ]);

        let core_row_0 = ExecutionState::STORAGE.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_1, core_row_0],
            state: vec![
                storage_contract_addr_row,
                stack_pop_row,
                storage_or_stack_0,
                storage_or_stack_1,
            ],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(StorageGadget {
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
    fn assign_and_constraint_sload() {
        let stack = Stack::from_slice(&[0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut storage_contract_addr: HashMap<u64, U256> = HashMap::new();
        storage_contract_addr.insert(0x01, U256::from(0x1111));
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(U256::from(0x1234)),
            call_id: 0x01,
            storage_contract_addr,
            ..WitnessExecHelper::new()
        };

        let mut trace = prepare_trace_step!(0, OpcodeId::SLOAD, stack);
        trace
            .storage
            .0
            .insert(U256::from(0xffff), U256::from(0x1234));

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
    #[test]
    fn assign_and_constraint_sstore() {
        let stack = Stack::from_slice(&[0x1234.into(), 0xffff.into()]);
        let stack_pointer = stack.0.len();
        let mut storage_contract_addr: HashMap<u64, U256> = HashMap::new();
        storage_contract_addr.insert(0x01, U256::from(0x1111));
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: None,
            call_id: 0x01,
            storage_contract_addr,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, OpcodeId::SSTORE, stack);
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
