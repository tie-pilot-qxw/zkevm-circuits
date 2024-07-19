use crate::arithmetic_circuit::operation;
use crate::execution::{
    AuxiliaryOutcome, CoreSinglePurposeOutcome, ExecutionConfig, ExecutionGadget, ExecutionState,
};
use crate::keccak_circuit::keccak_packed_multi::calc_keccak;
use crate::table::{extract_lookup_expression, LookupEntry};
use crate::util::{query_expression, ExpressionOutcome};
use crate::witness::arithmetic::Tag::U64Overflow;
use crate::witness::{assign_or_panic, public, state, Witness, WitnessExecHelper};
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, GethExecStep};
use gadgets::simple_is_zero::SimpleIsZero;
use gadgets::simple_seletor::{simple_selector_assign, SimpleSelector};
use gadgets::util::{select, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const NUM_ROW: usize = 3;
const STATE_STAMP_DELTA: u64 = 4;
const TAG_IDX: usize = 23;
const PC_DELTA: u64 = 1;

/// CODEINFO overview:
///   pop a value from the top of the stack: address, get the corresponding codehash or codesize according to the address,
/// and write the codehash to the top of the stack
///
/// CODEINFO Execution State layout is as follows
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// WARM_R means is_warm_read lookup,
/// WARM_W means is_warm_write lookup
/// PUBLIC means public lookup
/// STATE1 means state table lookup(pop)
/// STATE2 means state table lookup(pop)
/// ARITH means arithmetic u64overflow lookup
/// TAG1 means tag for EXTCODEHASH
/// TAG2 means tag for EXTCODESIZE
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col |  8 col   |
/// +---+-------+-------+-------+----------+
/// | 2 | WARM_R | WARM_W |     | PUBLIC(6)|
/// | 1 | STATE1 | STATE2 |ARITH|TAG1|TAG2 |
/// | 0 | DYNA_SELECTOR   | AUX |          |
/// +---+-------+-------+-------+----------+
pub struct CodeInfoGadget<F: Field> {
    _marker: PhantomData<F>,
}
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CodeInfoGadget<F>
{
    fn name(&self) -> &'static str {
        "CODEINFO"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CODEINFO
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
        let mut constraints = vec![];

        // get opcodeid tag and selector
        let extcodehash_tag = meta.query_advice(config.vers[TAG_IDX], Rotation::prev());
        let extcodesize_tag = meta.query_advice(config.vers[TAG_IDX + 1], Rotation::prev());
        let selector = SimpleSelector::new(&[extcodehash_tag, extcodesize_tag]);

        // constraint for opcode
        let opcode = meta.query_advice(config.opcode, Rotation::cur());
        constraints.push((
            "opcode is EXTCODEHASH or EXTCODESIZE".into(),
            selector.select(&[
                opcode.clone() - OpcodeId::EXTCODEHASH.as_u8().expr(),
                opcode - OpcodeId::EXTCODESIZE.as_u8().expr(),
            ]),
        ));

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

        let mut is_warm = 0.expr();
        for i in 0..2 {
            let entry = config.get_storage_lookup(meta, i, Rotation(-2));
            let mut is_write = true;
            if i == 0 {
                let extracted = extract_lookup_expression!(storage, entry.clone());
                is_warm = extracted.3;
                is_write = false;
            }
            constraints.append(&mut config.get_storage_full_constraints_with_tag(
                meta,
                entry,
                i + 2, // 前面有2个state
                NUM_ROW,
                0.expr(),
                0.expr(),
                stack_operands[0][0].clone(),
                stack_operands[0][1].clone(),
                state::Tag::AddrInAccessListStorage,
                is_write,
            ));
        }

        let gas_cost = select::expr(
            is_warm,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        // gas_left not overflow
        let current_gas_left = meta.query_advice(config.get_auxiliary().gas_left, Rotation::cur());
        let (tag, [gas_left_hi, gas_left_lo, overflow, overflow_inv]) = extract_lookup_expression!(
            arithmetic_tiny,
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 3, Rotation::prev())
        );
        let gas_left_not_overflow =
            SimpleIsZero::new(&overflow, &overflow_inv, "gas_left_u64_overflow".into());
        constraints.extend(gas_left_not_overflow.get_constraints());

        constraints.extend([
            (
                "tag is U64Overflow".into(),
                tag - (U64Overflow as u8).expr(),
            ),
            ("gas_left_hi == 0".into(), gas_left_hi.clone()),
            (
                "gas_left_lo = current_gas_left".into(),
                gas_left_lo - current_gas_left.clone(),
            ),
            (
                "gas_left not overflow".into(),
                1.expr() - gas_left_not_overflow.expr(),
            ),
        ]);

        // auxiliary constraints
        let delta = AuxiliaryOutcome {
            state_stamp: ExpressionOutcome::Delta(STATE_STAMP_DELTA.expr()),
            gas_left: ExpressionOutcome::Delta(-gas_cost),
            refund: ExpressionOutcome::Delta(0.expr()),
            ..Default::default()
        };
        constraints.extend(config.get_auxiliary_constraints(meta, NUM_ROW, delta));

        // core single constraints
        let delta = CoreSinglePurposeOutcome {
            pc: ExpressionOutcome::Delta(PC_DELTA.expr()),
            ..Default::default()
        };
        constraints.append(&mut config.get_next_single_purpose_constraints(meta, delta));

        // get public constraints
        let public_entry = config.get_public_lookup(meta, 0);
        constraints.extend(config.get_public_constraints(
            meta,
            public_entry.clone(),
            selector.select(&[
                (public::Tag::CodeHash as u8).expr(),
                (public::Tag::CodeSize as u8).expr(),
            ]),
            None,
            [
                Some(stack_operands[0][0].clone()),
                Some(stack_operands[0][1].clone()),
                Some(stack_operands[1][0].clone()),
                Some(stack_operands[1][1].clone()),
            ],
        ));

        constraints
    }

    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        let stack_lookup_addr = query_expression(meta, |meta| config.get_state_lookup(meta, 0));
        let stack_lookup_codeinfo = query_expression(meta, |meta| config.get_state_lookup(meta, 1));
        let public_lookup = query_expression(meta, |meta| config.get_public_lookup(meta, 0));
        let is_warm_read = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 0, Rotation(-2))
        });
        let is_warm_write = query_expression(meta, |meta| {
            config.get_storage_lookup(meta, 1, Rotation(-2))
        });
        let u64_overflow_rows = query_expression(meta, |meta| {
            config.get_arithmetic_tiny_lookup_with_rotation(meta, 3, Rotation::prev())
        });
        vec![
            ("stack addr lookup".into(), stack_lookup_addr),
            ("stack code info lookup".into(), stack_lookup_codeinfo),
            ("public lookup(code info)".into(), public_lookup),
            ("is_warm_read".into(), is_warm_read),
            ("is_warm_write".into(), is_warm_write),
            ("u64 overflow rows".into(), u64_overflow_rows),
        ]
    }

    fn gen_witness(&self, trace: &GethExecStep, current_state: &mut WitnessExecHelper) -> Witness {
        assert!(trace.op == OpcodeId::EXTCODEHASH || trace.op == OpcodeId::EXTCODESIZE);

        // get code address, and stack pop value
        let (stack_pop_addr, code_address) = current_state.get_pop_stack_row_value(&trace);

        // get bytecode with code_address
        let bytecode = current_state
            .bytecode
            .get(&code_address)
            .and_then(|b| Some(b.code()))
            .unwrap_or(vec![]);

        // calculate push value
        let (value, pub_tag) = if trace.op == OpcodeId::EXTCODEHASH {
            (calc_keccak(&bytecode), public::Tag::CodeHash)
        } else {
            (bytecode.len().into(), public::Tag::CodeSize)
        };

        assert_eq!(current_state.stack_top.unwrap(), value);
        let stack_push_row = current_state.get_push_stack_row(&trace, value);

        // row2
        let (is_warm_read, is_warm) = current_state.get_addr_access_list_read_row(code_address);
        let is_warm_write =
            current_state.get_addr_access_list_write_row(code_address, true, is_warm);

        //  get public row
        let public_row = current_state.get_public_code_info_row(pub_tag, code_address);

        let mut core_row_2 = current_state.get_core_row_without_versatile(&trace, 2);
        core_row_2.insert_public_lookup(0, &public_row);
        core_row_2.insert_storage_lookups([&is_warm_read, &is_warm_write]);

        // row1
        let (u64_overflow_rows, _) =
            operation::u64overflow::gen_witness::<F>(vec![current_state.gas_left.into()]);

        let mut core_row_1 = current_state.get_core_row_without_versatile(&trace, 1);
        core_row_1.insert_state_lookups([&stack_pop_addr, &stack_push_row]);
        core_row_1.insert_arithmetic_tiny_lookup(3, &u64_overflow_rows);

        // tag selector
        simple_selector_assign(
            &mut core_row_1,
            [TAG_IDX, TAG_IDX + 1],
            if trace.op == OpcodeId::EXTCODEHASH {
                0
            } else {
                1
            },
            |cell, value| assign_or_panic!(*cell, value.into()),
        );

        // row0
        let core_row_0 = ExecutionState::CODEINFO.into_exec_state_core_row(
            trace,
            current_state,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            state: vec![stack_pop_addr, stack_push_row, is_warm_read, is_warm_write],
            core: vec![core_row_2, core_row_1, core_row_0],
            arithmetic: u64_overflow_rows,
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CodeInfoGadget {
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

    fn run(
        stack: Stack,
        code_addr: U256,
        bytecode: HashMap<U256, Bytecode>,
        stack_top: U256,
        op: OpcodeId,
    ) {
        let stack_pointer = stack.0.len();
        let mut current_state = WitnessExecHelper {
            code_addr,
            bytecode,
            stack_pointer: stack.0.len(),
            stack_top: Some(stack_top),
            gas_left: 0x254023,
            ..WitnessExecHelper::new()
        };
        let gas_left_before_exec = current_state.gas_left + 0xA28;
        let mut trace = prepare_trace_step!(0, op, stack);
        trace.gas = gas_left_before_exec;
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                &trace,
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX] =
                Some(gas_left_before_exec.into());
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
        prover.assert_satisfied();
    }

    #[test]
    fn test_codeinfo() {
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let stack = Stack::from_slice(&[code_addr]);
        let mut bytecode = HashMap::new();
        let code = Bytecode::from(Vec::new().to_vec());
        bytecode.insert(code_addr, code);
        // empty code hash
        let hash = U256::from_str_radix(
            "0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470",
            16,
        )
        .unwrap();
        let len = U256::zero();

        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODEHASH,
        );
        run(stack, code_addr, bytecode, len, OpcodeId::EXTCODESIZE);
    }

    #[test]
    fn test_codeinfo2() {
        let code_addr =
            U256::from_str_radix("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512", 16).unwrap();
        let stack = Stack::from_slice(&[code_addr]);
        let mut bytecode = HashMap::new();
        let hex_code = hex::decode("6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea2646970667358fe1220fe7840966036100a633d188b84e1a14545ddea09878db189eb4a567d852807dd64736f6c63430008150033").unwrap();
        let code = Bytecode::from(hex_code.clone());
        bytecode.insert(code_addr, code);
        let hash = calc_keccak(hex_code.as_slice());
        let len = U256::from(hex_code.len());

        run(
            stack.clone(),
            code_addr,
            bytecode.clone(),
            hash,
            OpcodeId::EXTCODEHASH,
        );
        run(stack, code_addr, bytecode, len, OpcodeId::EXTCODESIZE);
    }
}
