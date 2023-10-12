use crate::execution::{AuxiliaryDelta, ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::{assign_or_panic, CurrentState, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, U256};
use gadgets::seletor::SimpleSelector;
use gadgets::util::{expr_from_bytes, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use trace_parser::Trace;

use super::{Auxiliary, CoreSinglePurposeOutcome};

const NUM_ROW: usize = 5;
const STATE_STAMP_DELTA: u64 = 3;
const STACK_POINTER_DELTA: i32 = -1;

#[derive(Debug, Clone, Copy)]
enum BitOp {
    And,
    Or,
    Xor,
}

pub struct AndOrXorGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for AndOrXorGadget<F>
{
    fn name(&self) -> &'static str {
        "AND_OR_XOR"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::AND_OR_XOR
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
        let Auxiliary { state_stamp, .. } = config.get_auxiliary();
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        let delta = AuxiliaryDelta {
            state_stamp: STATE_STAMP_DELTA.expr(),
            stack_pointer: STACK_POINTER_DELTA.expr(),
            ..Default::default()
        };
        let mut constraints = config.get_auxiliary_constraints(meta, NUM_ROW, delta);
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(1.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_core_single_purpose_constraints(meta, delta));

        let mut operands = vec![];
        let stack_pointer_delta = vec![0, -1, -1];
        for i in 0..3 {
            let entry = config.get_state_lookup(meta, i);
            constraints.append(&mut config.get_stack_constraints(
                meta,
                entry.clone(),
                i,
                NUM_ROW,
                stack_pointer_delta[i].expr(),
                i == 2,
            ));
            let (_, _, value_hi, value_lo, _, _, _, _) = extract_lookup_expression!(state, entry);
            operands.extend([value_hi, value_lo]);
        }
        let selector = SimpleSelector::new_selector(&[
            meta.query_advice(config.vers[29], Rotation::prev()),
            meta.query_advice(config.vers[30], Rotation::prev()),
            meta.query_advice(config.vers[31], Rotation::prev()),
        ]);
        constraints.extend(selector.gen_constraints());
        let bit_op = meta.query_advice(config.vers[25], Rotation::prev());
        constraints.push((
            "bit op is correct".into(),
            selector.select(&[
                bit_op.clone() - (BitOp::And as usize).expr(),
                bit_op.clone() - (BitOp::Or as usize).expr(),
                bit_op.clone() - (BitOp::Xor as usize).expr(),
            ]),
        ));

        constraints.extend([
            (
                "operand 0 hi".into(),
                expr_from_bytes(
                    &(16..32)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-2)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[0].clone(),
            ),
            (
                "operand 0 lo".into(),
                expr_from_bytes(
                    &(0..16)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-2)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[1].clone(),
            ),
            (
                "operand 1 hi".into(),
                expr_from_bytes(
                    &(16..32)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-3)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[2].clone(),
            ),
            (
                "operand 1 lo".into(),
                expr_from_bytes(
                    &(0..16)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-3)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[3].clone(),
            ),
            (
                "operand 2 hi".into(),
                expr_from_bytes(
                    &(16..32)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-4)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[4].clone(),
            ),
            (
                "operand 2 lo".into(),
                expr_from_bytes(
                    &(0..16)
                        .into_iter()
                        .map(|x| meta.query_advice(config.vers[x], Rotation(-4)).clone())
                        .collect::<Vec<_>>(),
                ) - operands[5].clone(),
            ),
        ]);

        constraints.extend([(
            "opcode is correct".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::AND.as_u8().expr(),
                opcode.clone() - OpcodeId::OR.as_u8().expr(),
                opcode.clone() - OpcodeId::XOR.as_u8().expr(),
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
        let stack_lookup_1 = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let stack_lookup_2 = query_expression(meta, |meta| config.get_state_lookup(meta, 2));
        let mut lookups = vec![
            ("stack pop a".into(), stack_lookup_0),
            ("stack pop b".into(), stack_lookup_1),
            ("stack push".into(), stack_lookup_2),
        ];
        (0..32).into_iter().for_each(|x| {
            lookups.push((
                format!("bitwise lookup {}", x).into(),
                query_expression(meta, |meta| config.get_bit_op_lookup(meta, x)),
            ))
        });
        lookups
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        let (stack_pop_0, a) = current_state.get_pop_stack_row_value();
        let (stack_pop_1, b) = current_state.get_pop_stack_row_value();
        let c = trace.stack_top.unwrap_or_default();
        let tag = match trace.op {
            OpcodeId::AND => {
                assert_eq!(c, a & b);
                BitOp::And
            }
            OpcodeId::OR => {
                assert_eq!(c, a | b);
                BitOp::Or
            }
            OpcodeId::XOR => {
                assert_eq!(c, a ^ b);
                BitOp::Xor
            }
            _ => panic!("not and or xor"),
        };

        let stack_push_0 = current_state.get_push_stack_row(c);

        let mut core_row_4 = current_state.get_core_row_without_versatile(4);
        let mut v_c = [0u8; 32];
        c.to_little_endian(&mut v_c);
        core_row_4.fill_versatile_with_values(
            &v_c.into_iter().map(|x| U256::from(x)).collect::<Vec<_>>(),
        );

        let mut core_row_3 = current_state.get_core_row_without_versatile(3);
        let mut v_b = [0u8; 32];
        b.to_little_endian(&mut v_b);
        core_row_3.fill_versatile_with_values(
            &v_b.into_iter().map(|x| U256::from(x)).collect::<Vec<_>>(),
        );

        let mut core_row_2 = current_state.get_core_row_without_versatile(2);
        let mut v_a = [0u8; 32];
        a.to_little_endian(&mut v_a);
        core_row_2.fill_versatile_with_values(
            &v_a.into_iter().map(|x| U256::from(x)).collect::<Vec<_>>(),
        );

        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_pop_1, &stack_push_0]);
        core_row_1.insert_bitwise_op_tag(tag as usize);
        let mut v = [U256::from(0); 3];
        v[tag as usize] = 1.into();
        assign_or_panic!(core_row_1.vers_29, v[0]);
        assign_or_panic!(core_row_1.vers_30, v[1]);
        assign_or_panic!(core_row_1.vers_31, v[2]);

        let core_row_0 = ExecutionState::AND_OR_XOR.into_exec_state_core_row(
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );
        Witness {
            core: vec![core_row_4, core_row_3, core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_pop_1, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(AndOrXorGadget {
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
        let stack = Stack::from_slice(&[0xffff.into(), 0xff00.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::XOR,
            stack_top: Some(0xff.into()),
        };
        current_state.copy_from_trace(&trace);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
