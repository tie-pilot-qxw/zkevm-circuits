pub mod add;
pub mod addmod;
pub mod and_or_xor;
pub mod byte;
pub mod call_context;
pub mod calldatacopy;
pub mod calldataload;
pub mod div_mod;
pub mod dup;
pub mod end_block;
pub mod eq;
pub mod gt;
pub mod iszero;
pub mod jump;
pub mod jumpdest;
pub mod jumpi;
pub mod lt;
pub mod memory;
pub mod mul;
pub mod mulmod;
pub mod not;
pub mod public_context;
pub mod push;
pub mod sgt;
pub mod slt;
pub mod stop;
pub mod storage;
pub mod sub;
pub mod tx_context;

use crate::core_circuit::{CoreCircuitConfig, CoreCircuitConfigArgs, NUM_VERS};
use crate::table::{BytecodeTable, LookupEntry};
use crate::witness::core::Row as CoreRow;
use crate::witness::Witness;
use crate::{execution::add::AddGadget, witness::CurrentState};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use gadgets::dynamic_selector::DynamicSelectorConfig;
use gadgets::is_zero_with_rotation::IsZeroWithRotationConfig;
use gadgets::util::Expr;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression, Selector, VirtualCells};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use strum::EnumCount;
use strum_macros::EnumCount as EnumCountMacro;
use trace_parser::Trace;

/// Get all execution gadgets by using this
macro_rules! get_every_execution_gadgets {
    () => {{
        vec![
            crate::execution::add::new(),
            crate::execution::push::new(),
            crate::execution::stop::new(),
            crate::execution::end_block::new(),
            crate::execution::iszero::new(),
            crate::execution::and_or_xor::new(),
            crate::execution::not::new(),
            crate::execution::jump::new(),
            crate::execution::jumpi::new(),
            crate::execution::jumpdest::new(),
            crate::execution::public_context::new(),
            crate::execution::tx_context::new(),
            crate::execution::memory::new(),
            crate::execution::storage::new(),
            crate::execution::call_context::new(),
            crate::execution::calldataload::new(),
            crate::execution::calldatacopy::new(),
            crate::execution::eq::new(),
            crate::execution::lt::new(),
            crate::execution::gt::new(),
            crate::execution::slt::new(),
            crate::execution::sgt::new(),
            crate::execution::byte::new(),
            crate::execution::dup::new(),
            crate::execution::mul::new(),
            crate::execution::sub::new(),
            crate::execution::div_mod::new(),
            crate::execution::addmod::new(),
            crate::execution::mulmod::new(),
        ]
    }};
}
pub(crate) use get_every_execution_gadgets;

#[derive(Clone)]
pub(crate) struct ExecutionConfig<F, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> {
    pub(crate) q_enable: Selector,
    // witness column of transaction index
    pub(crate) tx_idx: Column<Advice>,
    // witness column of call id
    pub(crate) call_id: Column<Advice>,
    // witness column of contract address
    pub(crate) code_addr: Column<Advice>,
    // witness column of program counter
    pub(crate) pc: Column<Advice>,
    // witness columns of opcode
    pub(crate) opcode: Column<Advice>,
    // witness column of opcode counter
    pub(crate) cnt: Column<Advice>,
    // witness columns of 32 versatile purposes
    pub(crate) vers: [Column<Advice>; NUM_VERS],
    // IsZero chip for witness column cnt
    pub(crate) cnt_is_zero: IsZeroWithRotationConfig<F>,
    // Selector of execution state
    pub(crate) execution_state_selector:
        DynamicSelectorConfig<F, { ExecutionState::COUNT }, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    // Tables used for lookup
    pub(crate) bytecode_table: BytecodeTable<F>,
}

// Columns in this struct should be used with Rotation::cur() and condition cnt_is_zero
#[derive(Clone)]
pub(crate) struct Auxiliary<F> {
    /// State stamp (counter) at the end of the execution state
    pub(crate) state_stamp: Column<Advice>,
    /// Stack pointer at the end of the execution state
    pub(crate) stack_pointer: Column<Advice>,
    /// Log stamp (counter) at the end of the execution state
    pub(crate) log_stamp: Column<Advice>,
    /// Gas left at the end of the execution state
    pub(crate) gas_left: Column<Advice>,
    /// Refund at the end of the execution state
    pub(crate) refund: Column<Advice>,
    /// Memory usage in chunk at the end of the execution state
    pub(crate) memory_chunk: Column<Advice>,
    /// Read only indicator (0/1) at the end of the execution state
    pub(crate) read_only: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    /// The number of columns used by auxiliary
    /// this+NUM_STATE_HI_COL+NUM_STATE_LO_COL should be no greater than 32
    pub(crate) const NUM_AUXILIARY: usize = 7;

    pub(crate) fn get_state_lookup(
        &self,
        meta: &mut VirtualCells<F>,
        num: usize,
    ) -> LookupEntry<F> {
        const WIDTH: usize = 8;
        let (
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        ) = (
            meta.query_advice(self.vers[num * WIDTH + 0], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 1], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 2], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 3], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 4], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 5], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 6], Rotation::prev()),
            meta.query_advice(self.vers[num * WIDTH + 7], Rotation::prev()),
        );
        LookupEntry::State {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
        }
    }

    pub(crate) fn get_bytecode_full_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (addr, pc, opcode, not_code, value_hi, value_lo, cnt, is_push) = (
            meta.query_advice(self.vers[24], Rotation::prev()),
            meta.query_advice(self.vers[25], Rotation::prev()),
            meta.query_advice(self.vers[26], Rotation::prev()),
            meta.query_advice(self.vers[27], Rotation::prev()),
            meta.query_advice(self.vers[28], Rotation::prev()),
            meta.query_advice(self.vers[29], Rotation::prev()),
            meta.query_advice(self.vers[30], Rotation::prev()),
            meta.query_advice(self.vers[31], Rotation::prev()),
        );
        LookupEntry::BytecodeFull {
            addr,
            pc,
            opcode,
            not_code,
            value_hi,
            value_lo,
            cnt,
            is_push,
        }
    }

    pub(crate) fn get_arithmetic_lookup(&self, meta: &mut VirtualCells<F>) -> LookupEntry<F> {
        let (hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3, tag) = (
            meta.query_advice(self.vers[0], Rotation(-2)),
            meta.query_advice(self.vers[1], Rotation(-2)),
            meta.query_advice(self.vers[2], Rotation(-2)),
            meta.query_advice(self.vers[3], Rotation(-2)),
            meta.query_advice(self.vers[4], Rotation(-2)),
            meta.query_advice(self.vers[5], Rotation(-2)),
            meta.query_advice(self.vers[6], Rotation(-2)),
            meta.query_advice(self.vers[7], Rotation(-2)),
            meta.query_advice(self.vers[8], Rotation(-2)),
        );
        LookupEntry::Arithmetic {
            tag,
            values: [hi_0, lo_0, hi_1, lo_1, hi_2, lo_2, hi_3, lo_3],
        }
    }

    pub(crate) fn get_auxiliary(&self) -> Auxiliary<F> {
        Auxiliary {
            state_stamp: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 0],
            stack_pointer: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 1],
            log_stamp: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 2],
            gas_left: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 3],
            refund: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 4],
            memory_chunk: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 5],
            read_only: self.vers[NUM_STATE_HI_COL + NUM_STATE_LO_COL + 6],
            _marker: PhantomData,
        }
    }
}

/// Execution Gadget for the configure and witness generation of an execution state
pub(crate) trait ExecutionGadget<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
>
{
    fn name(&self) -> &'static str;
    fn execution_state(&self) -> ExecutionState;
    /// Number of rows this execution state will use in core circuit
    fn num_row(&self) -> usize;
    /// Number of rows before and after the actual witness that cannot be used, which decides that
    /// the selector cannot be enabled
    fn unusable_rows(&self) -> (usize, usize);

    /// Get gate constraints for this execution state (without condition).
    /// Rotation::cur() in the constraints means the row that column config.cnt is 0
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)>;

    /// Get lookups for this execution state, prepared for merging lookups among all states
    /// Rotation::cur() in the lookups means the row that column config.cnt is 0
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)>;

    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness;
}

#[derive(Clone)]
pub(crate) struct ExecutionGadgets<
    F: Field,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    config: ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
}

impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadgets<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        config: ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
    ) -> Self {
        let gadgets: Vec<Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>> =
            get_every_execution_gadgets!();

        let mut lookups_to_merge = vec![];
        for gadget in &gadgets {
            // the constraints that all execution state requires, e.g., cnt=num_row-1 at the first row
            meta.create_gate(format!("EXECUTION_STATE_{}", gadget.name()), |meta| {
                let q_enable = meta.query_selector(config.q_enable);
                let num_row = gadget.num_row();
                let cnt_prev_state = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32));
                // cnt in first row of this state
                let cnt_first = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32 + 1));
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let execution_state_selector = config.execution_state_selector.selector(
                    meta,
                    gadget.execution_state() as usize,
                    Rotation::cur(),
                );
                let condition = q_enable * cnt_is_zero * execution_state_selector;
                vec![
                    (
                        "prev state last cnt = 0",
                        condition.clone() * cnt_prev_state,
                    ),
                    (
                        "this state first cnt is const",
                        condition.clone() * (cnt_first - (num_row - 1).expr()),
                    ),
                ]
            });
            // the constraints for the specific execution state, extracted from the gadget
            meta.create_gate(format!("EXECUTION_GADGET_{}", gadget.name()), |meta| {
                // constraints without condition
                let constraints = gadget.get_constraints(&config, meta);
                if constraints.is_empty() {
                    return vec![("placeholder due to no constraint".into(), 0.expr())];
                }
                let q_enable = meta.query_selector(config.q_enable);
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let execution_state_selector = config.execution_state_selector.selector(
                    meta,
                    gadget.execution_state() as usize,
                    Rotation::cur(),
                );
                let condition = q_enable * cnt_is_zero * execution_state_selector;
                constraints
                    .into_iter()
                    .map(|(s, e)| (s, condition.clone() * e))
                    .collect::<Vec<(String, Expression<F>)>>()
            });
            // extract lookups
            let execution_state = gadget.execution_state();
            let mut lookups = gadget
                .get_lookups(&config, meta)
                .into_iter()
                .map(|(string, lookup)| (string, lookup, execution_state))
                .collect();
            lookups_to_merge.append(&mut lookups);
        }
        // todo
        // merge lookups from all gadgets
        // currently there is no merge
        for (string, lookup, execution_state) in lookups_to_merge {
            match lookup {
                LookupEntry::BytecodeFull { .. } => {
                    meta.lookup_any(string, |meta| {
                        let q_enable = meta.query_selector(config.q_enable);
                        let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                        let execution_state_selector = config.execution_state_selector.selector(
                            meta,
                            execution_state as usize,
                            Rotation::cur(),
                        );
                        let condition = q_enable.clone() * cnt_is_zero * execution_state_selector;
                        let v = config.bytecode_table.get_lookup_vector(meta, lookup);
                        v.into_iter()
                            .map(|(left, right)| (condition.clone() * left, right))
                            .collect()
                    });
                }
                _ => (),
            };
        }
        ExecutionGadgets { config }
    }

    pub(crate) fn unusable_rows() -> (usize, usize) {
        let gadgets: Vec<Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>> =
            get_every_execution_gadgets!();
        let unusable_begin =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().0)).unwrap();
        let unusable_end =
            itertools::max(gadgets.iter().map(|gadget| gadget.unusable_rows().1)).unwrap();
        (unusable_begin, unusable_end)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, EnumCountMacro, Eq, Hash, PartialEq)]
pub enum ExecutionState {
    // zkevm internal states
    /// State that ends a block of transactions
    END_BLOCK, // it has to be the first state as it is the default padding state
    // opcode/operation successful states
    STOP,
    ADD,
    MUL,
    SUB,
    DIV_MOD,
    ADDMOD,
    MULMOD,
    PUSH,
    ISZERO,
    AND_OR_XOR,
    NOT,
    JUMP,
    JUMPDEST,
    //JUMP_ERR_OUTOFBOUND,
    JUMPI,
    PUBLIC_CONTEXT,
    TX_CONTEXT,
    MEMORY,
    STORAGE,
    CALL_CONTEXT,
    CALLDATALOAD,
    CALLDATACOPY,
    //CALLDATA_FROMPUBLIC,
    LOG_BYTES,
    LOG_TOPIC,
    EQ,
    LT,
    GT,
    SLT,
    SGT,
    DUP,
    SWAP,
    BYTE,
}

impl ExecutionState {
    // a mapping from opcode to execution state(s)
    pub fn from_opcode(opcode: OpcodeId) -> Vec<Self> {
        match opcode {
            OpcodeId::STOP => vec![Self::STOP],
            OpcodeId::ADD => vec![Self::ADD],
            OpcodeId::MUL => vec![Self::MUL],
            OpcodeId::SUB => vec![Self::SUB],
            OpcodeId::DIV | OpcodeId::MOD => vec![Self::DIV_MOD],
            OpcodeId::SDIV => {
                todo!()
            }
            OpcodeId::SMOD => {
                todo!()
            }
            OpcodeId::ADDMOD => vec![Self::ADDMOD],
            OpcodeId::MULMOD => vec![Self::MULMOD],
            OpcodeId::EXP => {
                todo!()
            }
            OpcodeId::SIGNEXTEND => {
                todo!()
            }
            OpcodeId::LT => vec![Self::LT],
            OpcodeId::GT => vec![Self::GT],
            OpcodeId::SLT => vec![Self::SLT],
            OpcodeId::SGT => vec![Self::SGT],
            OpcodeId::EQ => vec![Self::EQ],
            OpcodeId::ISZERO => vec![Self::ISZERO],
            OpcodeId::AND | OpcodeId::OR | OpcodeId::XOR => vec![Self::AND_OR_XOR],
            OpcodeId::NOT => vec![Self::NOT],
            OpcodeId::BYTE => vec![Self::BYTE],
            OpcodeId::CALLDATALOAD => vec![Self::CALLDATALOAD],
            OpcodeId::CALLDATACOPY => vec![Self::CALLDATACOPY],
            OpcodeId::CODESIZE => {
                todo!()
            }
            OpcodeId::CODECOPY => {
                todo!()
            }
            OpcodeId::SHL => {
                todo!()
            }
            OpcodeId::SHR => {
                todo!()
            }
            OpcodeId::SAR => {
                todo!()
            }
            OpcodeId::POP => {
                todo!()
            }
            OpcodeId::MLOAD | OpcodeId::MSTORE | OpcodeId::MSTORE8 => vec![Self::MEMORY],
            OpcodeId::JUMP => vec![Self::JUMP],
            OpcodeId::JUMPI => vec![Self::JUMPI],
            OpcodeId::PC => {
                todo!()
            }
            OpcodeId::MSIZE => {
                todo!()
            }
            OpcodeId::JUMPDEST => vec![Self::JUMPDEST],

            OpcodeId::PUSH1
            | OpcodeId::PUSH2
            | OpcodeId::PUSH3
            | OpcodeId::PUSH4
            | OpcodeId::PUSH5
            | OpcodeId::PUSH6
            | OpcodeId::PUSH7
            | OpcodeId::PUSH8
            | OpcodeId::PUSH9
            | OpcodeId::PUSH10
            | OpcodeId::PUSH11
            | OpcodeId::PUSH12
            | OpcodeId::PUSH13
            | OpcodeId::PUSH14
            | OpcodeId::PUSH15
            | OpcodeId::PUSH16
            | OpcodeId::PUSH17
            | OpcodeId::PUSH18
            | OpcodeId::PUSH19
            | OpcodeId::PUSH20
            | OpcodeId::PUSH21
            | OpcodeId::PUSH22
            | OpcodeId::PUSH23
            | OpcodeId::PUSH24
            | OpcodeId::PUSH25
            | OpcodeId::PUSH26
            | OpcodeId::PUSH27
            | OpcodeId::PUSH28
            | OpcodeId::PUSH29
            | OpcodeId::PUSH30
            | OpcodeId::PUSH31
            | OpcodeId::PUSH32 => vec![Self::PUSH],

            OpcodeId::DUP1
            | OpcodeId::DUP2
            | OpcodeId::DUP3
            | OpcodeId::DUP4
            | OpcodeId::DUP5
            | OpcodeId::DUP6
            | OpcodeId::DUP7
            | OpcodeId::DUP8
            | OpcodeId::DUP9
            | OpcodeId::DUP10
            | OpcodeId::DUP11
            | OpcodeId::DUP12
            | OpcodeId::DUP13
            | OpcodeId::DUP14
            | OpcodeId::DUP15
            | OpcodeId::DUP16 => vec![Self::DUP],

            OpcodeId::SWAP1
            | OpcodeId::SWAP2
            | OpcodeId::SWAP3
            | OpcodeId::SWAP4
            | OpcodeId::SWAP5
            | OpcodeId::SWAP6
            | OpcodeId::SWAP7
            | OpcodeId::SWAP8
            | OpcodeId::SWAP9
            | OpcodeId::SWAP10
            | OpcodeId::SWAP11
            | OpcodeId::SWAP12
            | OpcodeId::SWAP13
            | OpcodeId::SWAP14
            | OpcodeId::SWAP15
            | OpcodeId::SWAP16 => vec![Self::SWAP],

            OpcodeId::RETURN => {
                todo!()
            }
            OpcodeId::REVERT => {
                todo!()
            }
            OpcodeId::INVALID(_) => {
                todo!()
            }
            OpcodeId::SHA3 => {
                todo!()
            }
            OpcodeId::ADDRESS => {
                todo!()
            }
            OpcodeId::BALANCE => {
                todo!()
            }
            OpcodeId::ORIGIN | OpcodeId::GASPRICE => vec![Self::TX_CONTEXT],
            OpcodeId::CALLER | OpcodeId::CALLVALUE | OpcodeId::CALLDATASIZE => {
                vec![Self::CALL_CONTEXT]
            }

            OpcodeId::EXTCODESIZE => {
                todo!()
            }
            OpcodeId::EXTCODECOPY => {
                todo!()
            }
            OpcodeId::EXTCODEHASH => {
                todo!()
            }
            OpcodeId::RETURNDATASIZE => {
                todo!()
            }
            OpcodeId::RETURNDATACOPY => {
                todo!()
            }
            OpcodeId::BLOCKHASH => {
                todo!()
            }
            OpcodeId::COINBASE
            | OpcodeId::TIMESTAMP
            | OpcodeId::NUMBER
            | OpcodeId::GASLIMIT
            | OpcodeId::CHAINID
            | OpcodeId::BASEFEE => vec![Self::PUBLIC_CONTEXT],
            OpcodeId::DIFFICULTY => {
                todo!()
            }
            OpcodeId::SELFBALANCE => {
                todo!()
            }
            OpcodeId::SLOAD | OpcodeId::SSTORE => vec![Self::STORAGE],
            OpcodeId::GAS => {
                todo!()
            }
            //LOG TOPIC LOG BYTES
            OpcodeId::LOG0 | OpcodeId::LOG1 | OpcodeId::LOG2 | OpcodeId::LOG3 | OpcodeId::LOG4 => {
                vec![Self::LOG_BYTES]
            }
            OpcodeId::CREATE => {
                todo!()
            }
            OpcodeId::CREATE2 => {
                todo!()
            }
            OpcodeId::CALL => {
                todo!()
            }
            OpcodeId::CALLCODE => {
                todo!()
            }
            OpcodeId::DELEGATECALL => {
                todo!()
            }
            OpcodeId::STATICCALL => {
                todo!()
            }
            OpcodeId::SELFDESTRUCT => {
                todo!()
            }
        }
    }
}

#[cfg(test)]
mod test {
    /// Used in `mod test` under each execution gadget file
    /// Generate `TestCircuit` for the execution gadget
    macro_rules! generate_execution_gadget_test_circuit {
        () => {
            use super::*;
            use crate::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
            use crate::core_circuit::NUM_VERS;
            use crate::table::BytecodeTable;
            use crate::util::{assign_advice_or_fixed, convert_u256_to_64_bytes, SubCircuitConfig};
            use eth_types::evm_types::{OpcodeId, Stack};
            use gadgets::dynamic_selector::DynamicSelectorChip;
            use gadgets::is_zero::IsZeroInstruction;
            use gadgets::is_zero_with_rotation::IsZeroWithRotationChip;
            use gadgets::util::Expr;
            use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
            use halo2_proofs::dev::MockProver;
            use halo2_proofs::halo2curves::bn256::Fr;
            use halo2_proofs::plonk::{Advice, Circuit, Column, Error, Selector};
            use halo2_proofs::poly::Rotation;
            use std::collections::HashMap;
            #[derive(Clone, Default, Debug)]
            struct TestCircuit<F> {
                witness: Witness,
                _marker: PhantomData<F>,
            }
            impl<F: Field> Circuit<F> for TestCircuit<F> {
                type Config = ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    Self::default()
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let q_enable = meta.complex_selector();
                    let cnt = meta.advice_column();
                    let cnt_is_zero = IsZeroWithRotationChip::configure(
                        meta,
                        |meta| meta.query_selector(q_enable),
                        cnt,
                    );
                    let vers: [Column<Advice>; NUM_VERS] =
                        std::array::from_fn(|_| meta.advice_column());
                    let execution_state_selector = DynamicSelectorChip::configure(
                        meta,
                        |meta| {
                            let q_enable = meta.query_selector(q_enable);
                            let ans = cnt_is_zero.expr_at(meta, Rotation::cur());
                            q_enable * ans
                        },
                        vers[0..NUM_STATE_HI_COL].try_into().unwrap(),
                        vers[NUM_STATE_HI_COL..NUM_STATE_HI_COL + NUM_STATE_LO_COL]
                            .try_into()
                            .unwrap(),
                    );
                    let q_enable_bytecode = meta.complex_selector();
                    let bytecode_table = BytecodeTable::construct(meta, q_enable_bytecode);
                    let config = ExecutionConfig {
                        q_enable,
                        tx_idx: meta.advice_column(),
                        call_id: meta.advice_column(),
                        code_addr: meta.advice_column(),
                        pc: meta.advice_column(),
                        opcode: meta.advice_column(),
                        cnt,
                        vers,
                        cnt_is_zero,
                        execution_state_selector,
                        bytecode_table,
                    };
                    let gadget = new();
                    meta.create_gate("TEST", |meta| {
                        let constraints = gadget.get_constraints(&config, meta);
                        if constraints.is_empty() {
                            return vec![("placeholder due to no constraint".into(), 0u8.expr())];
                        }
                        let q_enable = meta.query_selector(q_enable);
                        let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                        let condition = q_enable * cnt_is_zero;
                        constraints
                            .into_iter()
                            .map(|(s, e)| (s, condition.clone() * e))
                            .collect::<Vec<(String, Expression<F>)>>()
                    });
                    config
                }

                fn synthesize(
                    &self,
                    config: Self::Config,
                    mut layouter: impl Layouter<F>,
                ) -> Result<(), Error> {
                    layouter.assign_region(
                        || "test",
                        |mut region| {
                            region.name_column(|| "CORE_tx_idx", config.tx_idx);
                            region.name_column(|| "CORE_call_id", config.call_id);
                            region.name_column(|| "CORE_code_addr", config.code_addr);
                            region.name_column(|| "CORE_pc", config.pc);
                            region.name_column(|| "CORE_opcode", config.opcode);
                            region.name_column(|| "CORE_cnt", config.cnt);
                            for i in 0..NUM_VERS {
                                region.name_column(|| format!("CORE_vers_{}", i), config.vers[i]);
                            }
                            config
                                .cnt_is_zero
                                .annotate_columns_in_region(&mut region, "CORE_cnt_is_zero");
                            for (offset, row) in self.witness.core.iter().enumerate() {
                                let cnt_is_zero: IsZeroWithRotationChip<F> =
                                    IsZeroWithRotationChip::construct(config.cnt_is_zero);
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.tx_idx,
                                    config.tx_idx,
                                )?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.call_id,
                                    config.call_id,
                                )?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.code_addr,
                                    config.code_addr,
                                )?;
                                assign_advice_or_fixed(&mut region, offset, &row.pc, config.pc)?;
                                assign_advice_or_fixed(
                                    &mut region,
                                    offset,
                                    &row.opcode.as_u8().into(),
                                    config.opcode,
                                )?;
                                assign_advice_or_fixed(&mut region, offset, &row.cnt, config.cnt)?;
                                for (i, value) in [
                                    &row.vers_0,
                                    &row.vers_1,
                                    &row.vers_2,
                                    &row.vers_3,
                                    &row.vers_4,
                                    &row.vers_5,
                                    &row.vers_6,
                                    &row.vers_7,
                                    &row.vers_8,
                                    &row.vers_9,
                                    &row.vers_10,
                                    &row.vers_11,
                                    &row.vers_12,
                                    &row.vers_13,
                                    &row.vers_14,
                                    &row.vers_15,
                                    &row.vers_16,
                                    &row.vers_17,
                                    &row.vers_18,
                                    &row.vers_19,
                                    &row.vers_20,
                                    &row.vers_21,
                                    &row.vers_22,
                                    &row.vers_23,
                                    &row.vers_24,
                                    &row.vers_25,
                                    &row.vers_26,
                                    &row.vers_27,
                                    &row.vers_28,
                                    &row.vers_29,
                                    &row.vers_30,
                                    &row.vers_31,
                                ]
                                .into_iter()
                                .enumerate()
                                {
                                    assign_advice_or_fixed(
                                        &mut region,
                                        offset,
                                        &value.unwrap_or_default(),
                                        config.vers[i],
                                    )?;
                                }
                                cnt_is_zero.assign(
                                    &mut region,
                                    offset,
                                    Value::known(F::from_uniform_bytes(&convert_u256_to_64_bytes(
                                        &row.cnt,
                                    ))),
                                )?;
                            }
                            let gadget: Box<
                                dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
                            > = new();
                            // only enable the row with cnt=0
                            let enabled_row = gadget.unusable_rows().0 + gadget.num_row() - 1;
                            config.q_enable.enable(&mut region, enabled_row)?;
                            Ok(())
                        },
                    )
                }
            }
            impl<F: Field> TestCircuit<F> {
                pub fn new(witness: Witness) -> Self {
                    Self {
                        witness,
                        _marker: PhantomData,
                    }
                }
            }
        };
    }
    /// Used in `fn text_xx()` under each execution gadget file
    /// Generate witness and mock prover for the execution gadget
    macro_rules! prepare_witness_and_prover {
        ($trace:expr, $current_state:expr, $padding_begin_row:expr, $padding_end_row:expr) => {{
            let gadget: Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> = new();
            let mut witness = gadget.gen_witness(&$trace, &mut $current_state);
            assert_eq!(gadget.num_row(), witness.core.len());
            for _ in 0..gadget.unusable_rows().0 {
                witness.core.insert(0, $padding_begin_row.clone());
            }
            for _ in 0..gadget.unusable_rows().1 {
                witness.core.push($padding_end_row.clone());
            }
            let k = 8;
            let circuit = TestCircuit::<Fr>::new(witness.clone());
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            (witness, prover)
        }};
    }
    pub(crate) use {generate_execution_gadget_test_circuit, prepare_witness_and_prover};
}
