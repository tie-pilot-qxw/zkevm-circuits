use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::public::Tag;
use crate::witness::{assign_or_panic, public, Witness, WitnessExecHelper};
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;
use eth_types::{Field, U256};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::SimpleSelector;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

use crate::execution::{AuxiliaryDelta, CoreSinglePurposeOutcome};

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 1;
const STACK_POINTER_DELTA: i32 = 1;

#[derive(Debug, Clone, Copy)]
enum BitOp {
    TIMESTAMP,
    NUMBER,
    COINBASE,
    GASLIMIT,
    CHAINID,
    BASEFEE,
}

/// PublicContextGadget
/// STATE0 record value
/// TAGSELECTOR 6 columns
/// TAG 1 column, means public tag (column 24)
/// TX_IDX_0 1 column,default 0, means public table tx_idx (column 25)
/// VALUE_HI 1 column , means public table value0 (column 26)
/// VALUE_LOW 1 column, means public table value1 (column 27)
/// VALUE_2 1 column , means public table value2 , here default 0 (column 28)
/// VALUE_3 1 column ,means public table value3 , here default 0 (column 29)
/// IS_ORIGIN 1 column (column 0)
/// INV OF HI 1 column (cllumn 1)
/// IS_GASPRICE 1 column (column 2)
/// INV OF LO 1 column (cloumn 3)
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | IS_ORIGIN | INV OF HI| IS_GASPRICE | INV OF LO | 4 col (unused) | 8 col (unused) | 8 col (unused) |TAG | TX_IDX_0 | VALUE_HI | VALUE_LOW | VALUE_2 | VALUE_3 |
/// | 1 | STATE0| TAGSELECTOR |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
pub struct PublicContextGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for PublicContextGadget<F>
{
    fn name(&self) -> &'static str {
        "PUBLIC_CONTEXT"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::PUBLIC_CONTEXT
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
            (1 as i32).expr(),
            true,
        ));
        // value_hi,value_lo constraints
        let (_, _, state_value_hi, state_value_lo, _, _, _, _) =
            extract_lookup_expression!(state, entry);
        let public_entry = config.get_public_lookup(meta);
        let (public_tag, tx_idx_or_number_diff, values) =
            extract_lookup_expression!(public, public_entry);
        // value[2] =0 values[3] = 0
        constraints.extend([
            ("values[2] = 0".into(), values[2].clone()),
            ("values[3] = 0".into(), values[3].clone()),
        ]);
        let timestamp_tag = meta.query_advice(config.vers[8], Rotation::prev());
        let number_tag = meta.query_advice(config.vers[9], Rotation::prev());
        let coinbase_tag = meta.query_advice(config.vers[10], Rotation::prev());
        let gaslimit_tag = meta.query_advice(config.vers[11], Rotation::prev());
        let chainid_tag = meta.query_advice(config.vers[12], Rotation::prev());
        let basefee_tag = meta.query_advice(config.vers[13], Rotation::prev());
        // public tag constraints
        constraints.extend([(
            "tag constraints".into(),
            public_tag
                - timestamp_tag.clone() * F::from(public::Tag::BlockTimestamp as u64)
                - number_tag.clone() * F::from(Tag::BlockNumber as u64)
                - coinbase_tag.clone() * F::from(Tag::BlockCoinbase as u64)
                - gaslimit_tag.clone() * F::from(Tag::BlockGasLimit as u64)
                - chainid_tag.clone() * F::from(Tag::ChainId as u64)
                - basefee_tag.clone() * F::from(Tag::BlockBaseFee as u64),
        )]);
        let value_hi = values[0].clone();
        let value_lo = values[1].clone();
        let value_hi_inv = meta.query_advice(config.vers[1], Rotation(-2));
        let value_lo_inv = meta.query_advice(config.vers[3], Rotation(-2));
        // value_hi constraints
        let is_value_hi_zero =
            SimpleIsZero::new(&value_hi, &value_hi_inv, String::from("value_hi"));
        constraints.extend(is_value_hi_zero.get_constraints());
        // value_lo constraints
        let is_value_lo_zero =
            SimpleIsZero::new(&value_lo, &value_lo_inv, String::from("value_lo"));
        constraints.extend(is_value_lo_zero.get_constraints());
        constraints.extend([
            ("state_value_hi ".into(), state_value_hi - value_hi),
            ("state_value_lo".into(), state_value_lo - value_lo),
        ]);
        // txid * (is_origin + is_gasprice) = 0
        let is_origin = meta.query_advice(config.vers[0], Rotation(-2));
        let is_gasprice = meta.query_advice(config.vers[2], Rotation(-2));
        constraints.extend([(
            "tx_id_o *(is_origin + is_gasprice)".into(),
            tx_idx_or_number_diff * (is_origin + is_gasprice),
        )]);
        let selector = SimpleSelector::new(&[
            timestamp_tag,
            number_tag,
            coinbase_tag,
            gaslimit_tag,
            chainid_tag,
            basefee_tag,
        ]);
        let public_context_tag = selector.select(&[
            opcode.clone() - (OpcodeId::TIMESTAMP.as_u64()).expr(),
            opcode.clone() - (OpcodeId::NUMBER.as_u64()).expr(),
            opcode.clone() - (OpcodeId::COINBASE.as_u64()).expr(),
            opcode.clone() - (OpcodeId::GASLIMIT.as_u64()).expr(),
            opcode.clone() - (OpcodeId::CHAINID.as_u64()).expr(),
            opcode.clone() - (OpcodeId::BASEFEE.as_u64()).expr(),
        ]);
        // tag constraints
        constraints.extend([("opCode constraints".into(), public_context_tag)]);
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
            ("public context value lookup".into(), public_context_lookup),
        ]
    }
    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        let next_stack_top_value = current_state.stack_top.unwrap_or_default();
        let stack_push_0 = current_state.get_push_stack_row(trace, next_stack_top_value);
        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        let value_hi = (next_stack_top_value >> 128).as_u128();
        let value_hi_inv = U256::from_little_endian(
            F::from_u128(value_hi)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );
        let value_lo = next_stack_top_value.low_u128();
        let value_lo_inv = U256::from_little_endian(
            F::from_u128(value_lo)
                .invert()
                .unwrap_or(F::ZERO)
                .to_repr()
                .as_ref(),
        );

        let (public_tag, tag) = match trace.op {
            OpcodeId::TIMESTAMP => (public::Tag::BlockTimestamp, BitOp::TIMESTAMP),
            OpcodeId::NUMBER => (public::Tag::BlockNumber, BitOp::NUMBER),
            OpcodeId::COINBASE => (public::Tag::BlockCoinbase, BitOp::COINBASE),
            OpcodeId::GASLIMIT => (public::Tag::BlockGasLimit, BitOp::GASLIMIT),
            OpcodeId::CHAINID => (public::Tag::ChainId, BitOp::CHAINID),
            OpcodeId::BASEFEE => (public::Tag::BlockBaseFee, BitOp::BASEFEE),
            _ => panic!("not PUBLIC_CONTEXT op"),
        };
        // core_row_2
        core_row_2.insert_public_lookup(&public::Row {
            tag: public_tag,
            tx_idx_or_number_diff: Some(0.into()),
            value_0: Some(U256::from(value_hi)),
            value_1: Some(U256::from(value_lo)),
            value_2: Some(0.into()),
            value_3: Some(0.into()),
            ..Default::default()
        });
        // is_origin
        assign_or_panic!(core_row_2.vers_0, 0.into());
        // inv of ih
        assign_or_panic!(core_row_2.vers_1, value_hi_inv);
        // is_gasprice
        assign_or_panic!(core_row_2.vers_2, 0.into());
        //inv of lo
        assign_or_panic!(core_row_2.vers_3, value_lo_inv);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);

        core_row_1.insert_state_lookups([&stack_push_0]);

        let mut v = [U256::from(0); 6];
        v[tag as usize] = 1.into();
        // tag selector
        assign_or_panic!(core_row_1.vers_8, v[0]);
        assign_or_panic!(core_row_1.vers_9, v[1]);
        assign_or_panic!(core_row_1.vers_10, v[2]);
        assign_or_panic!(core_row_1.vers_11, v[3]);
        assign_or_panic!(core_row_1.vers_12, v[4]);
        assign_or_panic!(core_row_1.vers_13, v[5]);
        // core row 2
        let core_row_0 = ExecutionState::PUBLIC_CONTEXT.into_exec_state_core_row(
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
    Box::new(PublicContextGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();

    fn run(op_code: OpcodeId) {
        let stack = Stack::from_slice(&[]);
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            stack_pointer: stack.0.len(),
            stack_top: Some(0xff.into()),
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
    #[test]
    fn assign_opcode_run() {
        run(OpcodeId::CHAINID);
        run(OpcodeId::TIMESTAMP);
        run(OpcodeId::NUMBER);
        run(OpcodeId::COINBASE);
        run(OpcodeId::GASLIMIT);
        run(OpcodeId::BASEFEE);
    }
}
