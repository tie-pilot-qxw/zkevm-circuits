use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::Tag;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use super::{AuxiliaryDelta, CoreSinglePurposeOutcome};

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;

/// TxContextGadget deal OpCodeId:{ORIGIN,GASPRICE}
/// STATE0 record value
/// TAGSELECTOR 2 columns
/// PUBLIC 6 columns, including:
/// - TAG 1 column, means public tag (column 26)
/// - TX_IDX_0 1 column,default 0, means public table tx_idx (column 27)
/// - VALUE_HI 1 column , means public table value0 (column 28)
/// - VALUE_LOW 1 column, means public table value1 (column 29)
/// - VALUE_2 1 column , means public table value2 , here from_high (column 30)
/// - VALUE_3 1 column ,means public table value3 , here from_low (column 31)
/// +---+-------+-------+-------+-------+-------+
/// |cnt| 8 col | 8 col | 8 col | 2 col | 6 col |
/// +---+-------+-------+-------+---------------+
/// | 2 |                               |PUBLIC |
/// | 1 | STATE0| TAGSELECTOR |                 |
/// | 0 | DYNA_SELECTOR        | AUX            |
/// +---+-------+-------+-------+-------+-------+
pub struct TxContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for TxContextGadget<F>
{
    fn name(&self) -> &'static str {
        "TX_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::TX_CONTEXT
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
        let tx_idx = meta.query_advice(config.tx_idx, Rotation::cur());
        let auxiliary_delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        // auxiliary constraints
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, auxiliary_delta);
        // core single constraints
        let core_single_delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints
            .append(&mut config.get_core_single_purpose_constraints(meta, core_single_delta));
        // stack constraints
        let entry = config.get_state_lookup(meta, 0);
        constraints.append(&mut config.get_stack_constraints(
            meta,
            entry.clone(),
            0,
            NUM_ROW,
            (1i32).expr(),
            true,
        ));
        // value_hi,value_lo constraints
        let (_, _, state_value_hi, state_value_lo, _, _, _, _) =
            extract_lookup_expression!(state, entry);
        let public_entry = config.get_public_lookup(meta);
        let origin_tag = meta.query_advice(config.vers[8], Rotation::prev());
        let gasprice_tag = meta.query_advice(config.vers[9], Rotation::prev());
        let selector = SimpleSelector::new(&[origin_tag.clone(), gasprice_tag.clone()]);
        // pubic lookup constraints
        constraints.extend(config.get_public_constraints(
            meta,
            public_entry,
            selector.select(&[
                (Tag::TxFromValue as u64).expr(),
                (Tag::TxGasPrice as u64).expr(),
            ]),
            Some(tx_idx.clone()),
            [Some(state_value_hi), Some(state_value_lo), None, None],
        ));
        // opcode constraints
        constraints.extend([(
            "opcode constraints".into(),
            opcode
                - selector.select(&[
                    (OpcodeId::ORIGIN.as_u8()).expr(),
                    (OpcodeId::GASPRICE.as_u8()).expr(),
                ]),
        )]);
        constraints
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_0 = query_expression(meta, |meta| config.get_state_lookup(meta, 0));

        let public_context_lookup = query_expression(meta, |meta| config.get_public_lookup(meta));
        vec![
            ("stack push value lookup".into(), stack_lookup_0),
            ("tx context value lookup".into(), public_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let next_stack_top_value = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, next_stack_top_value);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let value_hi = (next_stack_top_value >> 128).as_u128();
        let value_lo = next_stack_top_value.low_u128();
        let (public_tag, tag, value_public_2, value_public_3) = match trace.op {
            OpcodeId::ORIGIN => (
                Tag::TxFromValue,
                0usize,
                current_state.tx_value >> 128,
                current_state.tx_value.low_u128().into(),
            ),
            OpcodeId::GASPRICE => (Tag::TxGasPrice, 1, U256::from(0), U256::from(0)),
            _ => panic!("not ORIGIN or GASPRICE"),
        };
        // core_row_2
        core_row_2.insert_public_lookup(&public::Row {
            tag: public_tag,
            tx_idx_or_number_diff: Some(U256::from(current_state.tx_idx)),
            value_0: Some(U256::from(value_hi)),
            value_1: Some(U256::from(value_lo)),
            value_2: Some(value_public_2),
            value_3: Some(value_public_3),
            ..Default::default()
        });
        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_push_0]);

        // tag selector
        simple_selector_assign(
            [&mut core_row_1.vers_8, &mut core_row_1.vers_9],
            tag,
            |cell, value| assign_or_panic!(*cell, value.into()),
        );
        // core row 0
        let core_row_0 = ExecutionState::TX_CONTEXT.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(TxContextGadget {
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
    fn assign_opcode_run() {
        run(OpcodeId::ORIGIN);
        run(OpcodeId::GASPRICE);
    }

    fn run(op_code: OpcodeId) {
        let stack = Stack::from_slice(&[0.into(), 1.into()]);
        let stack_pointer = stack.0.len();
        let mut sender = HashMap::new();
        sender.insert(0_u64, U256::max_value() - 1);
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
            sender,
            ..WitnessExecHelper::new()
        };
        let trace = prepare_trace_step!(0, op_code, stack);
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
