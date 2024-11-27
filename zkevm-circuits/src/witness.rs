// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use halo2_proofs::halo2curves::bn256::Fr;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Write;

use eth_types::evm_types::OpcodeId;
use eth_types::geth_types::ChunkData;
use eth_types::{Field, GethExecStep, U256};

use crate::arithmetic_circuit::ArithmeticCircuit;
use crate::bitwise_circuit::BitwiseCircuit;
use crate::bytecode_circuit::BytecodeCircuit;
use crate::constant::{
    BYTECODE_NUM_PADDING, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
    POSEIDON_HASH_BYTES_IN_FIELD,
};
use crate::copy_circuit::CopyCircuit;
use crate::core_circuit::CoreCircuit;
use crate::execution::{get_every_execution_gadgets, ExecutionGadget, ExecutionState};
use crate::exp_circuit::ExpCircuit;
use crate::poseidon_circuit::HASH_BLOCK_STEP_SIZE;
use crate::public_circuit::PublicCircuit;
use crate::state_circuit::ordering::state_to_be_limbs;
use crate::state_circuit::StateCircuit;
use crate::table::PoseidonTable;
use crate::util::{hash_code_poseidon, SubCircuit};
use crate::witness::poseidon::{
    get_hash_input_from_u8s_default, get_poseidon_row_from_stream_input,
};
use crate::witness::public::public_rows_to_instance;
pub mod arithmetic;
pub mod bitwise;
pub mod bytecode;
pub mod copy;
pub mod core;
pub(crate) mod exec_helper;
pub mod exp;
pub mod fixed;
pub mod poseidon;
pub mod public;
pub mod state;
mod util;

pub use exec_helper::WitnessExecHelper;
pub use util::{get_and_insert_shl_shr_rows, get_and_insert_signextend_rows};

#[derive(Debug, Default, Clone)]
pub struct Witness {
    pub bytecode: Vec<bytecode::Row>,
    pub copy: Vec<copy::Row>,
    pub core: Vec<core::Row>,
    pub exp: Vec<exp::Row>,
    pub public: Vec<public::Row>,
    pub state: Vec<state::Row>,
    pub arithmetic: Vec<arithmetic::Row>,
    pub bitwise: Vec<bitwise::Row>,
    // keccak inputs, Keccak needs to use challenge to calculate the RLC value, and challenge can
    // only be used inside the circuit,so all the inputs that need to be calculated hash are saved here,
    // and then keccak_circuit will calculate rows based on the inputs in the synthesize_sub method inside the circuit.
    pub keccak: Vec<Vec<u8>>,
    // we omit fixed table rows on purpose due to its large size
    // poseidon circuit input
    pub poseidon: Vec<poseidon::Row>,
}

macro_rules! assign_or_panic {
    ($opt: expr, $value: expr) => {
        match $opt {
            None => $opt = Some($value),
            Some(_) => panic!("Trying to assign to an already set Option!"),
        }
    };
}

pub(crate) use assign_or_panic;

impl Witness {
    pub fn append(&mut self, mut witness: Witness) {
        self.bytecode.append(&mut witness.bytecode);
        self.copy.append(&mut witness.copy);
        self.core.append(&mut witness.core);
        self.exp.append(&mut witness.exp);
        self.public.append(&mut witness.public);
        self.state.append(&mut witness.state);
        self.bitwise.append(&mut witness.bitwise);
        self.arithmetic.append(&mut witness.arithmetic);
        #[cfg(not(feature = "no_hash_circuit"))]
        self.keccak.append(&mut witness.keccak);
    }

    fn gen_bytecode_witness(
        addr: U256,
        mut machine_code: Vec<u8>,
        hash: U256,
    ) -> Vec<bytecode::Row> {
        let mut res = vec![];
        let mut pc = 0;
        let real_machine_code_len = machine_code.len();
        while pc < machine_code.len() {
            let op = OpcodeId::from(machine_code[pc]);
            let mut this_op = vec![];
            if op.is_push_with_data() {
                let mut cnt = (op.as_u64() - OpcodeId::PUSH0.as_u64()) as usize;
                // if pc >= machine_code.len(), the number of bytes pushed by the pushX instruction is less than X
                // then padding value
                if pc + cnt >= machine_code.len() {
                    let push_padding_zero_num = pc + cnt - machine_code.len() + 1;
                    machine_code.extend(vec![0; push_padding_zero_num]);
                    // add STOP
                    machine_code.push(OpcodeId::STOP.as_u8())
                }

                let mut acc_hi = 0u128;
                let mut acc_lo = 0u128;
                this_op.push(bytecode::Row {
                    addr: Some(addr),
                    pc: Some(pc.into()),
                    bytecode: Some(op.as_u64().into()),
                    acc_hi: Some(acc_hi.into()),
                    acc_lo: Some(acc_lo.into()),
                    cnt: Some(cnt.into()),
                    is_high: Some((if cnt >= 16 { 1 } else { 0 }).into()),
                    hash: Some(hash.into()),
                    length: Some(real_machine_code_len.into()),
                    is_padding: Some(0.into()),
                    ..Default::default()
                });
                pc += 1;
                while cnt > 0 && pc < machine_code.len() {
                    cnt -= 1;
                    if cnt >= 16 {
                        acc_hi = acc_hi * 256 + machine_code[pc] as u128;
                    } else {
                        acc_lo = acc_lo * 256 + machine_code[pc] as u128;
                    }
                    this_op.push(bytecode::Row {
                        addr: Some(addr),
                        pc: Some(pc.into()),
                        bytecode: Some(machine_code[pc].into()),
                        acc_hi: Some(acc_hi.into()),
                        acc_lo: Some(acc_lo.into()),
                        cnt: Some(cnt.into()),
                        is_high: Some((if cnt >= 16 { 1 } else { 0 }).into()),
                        hash: Some(hash.into()),
                        length: Some(real_machine_code_len.into()),
                        is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                        ..Default::default()
                    });
                    pc += 1;
                }
                let (value_hi, value_lo) = this_op.last().map(|x| (x.acc_hi, x.acc_lo)).unwrap();
                for i in &mut this_op {
                    i.value_hi = value_hi;
                    i.value_lo = value_lo;
                }
            } else {
                this_op.push(bytecode::Row {
                    addr: Some(addr),
                    pc: Some(pc.into()),
                    bytecode: Some(op.as_u64().into()),
                    cnt: Some(0.into()),
                    value_hi: Some(0.into()),
                    value_lo: Some(0.into()),
                    acc_hi: Some(0.into()),
                    acc_lo: Some(0.into()),
                    is_high: Some(0.into()),
                    hash: Some(hash.into()),
                    length: Some(real_machine_code_len.into()),
                    is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                    ..Default::default()
                });
                pc += 1;
            }
            res.append(&mut this_op);
        }

        // to uniformly process all bytecodes, add padding to all bytecodes
        let all_zero_padding_num = BYTECODE_NUM_PADDING - (pc - real_machine_code_len);
        for _ in 0..all_zero_padding_num {
            res.push(bytecode::Row {
                addr: Some(addr),
                pc: Some(pc.into()),
                hash: Some(hash.into()),
                length: Some(real_machine_code_len.into()),
                is_padding: Some(((pc >= real_machine_code_len) as u8).into()),
                ..Default::default()
            });
            pc += 1;
        }
        res
    }

    /// Generate witness of all blocks related data, such as bytecode and public table
    fn insert_block_related(&mut self, chunk_data: &ChunkData) {
        self.public
            .append(&mut public::Row::from_chunk_data(&chunk_data).unwrap());
        let mut bytecode_set = HashSet::new();

        for account in chunk_data.blocks.iter().flat_map(|b| b.accounts.iter()) {
            let machine_code = account.code.as_ref();
            let code_hash = hash_code_poseidon(machine_code);

            if !account.code.is_empty() && !bytecode_set.contains(&(account.address, code_hash)) {
                let mut bytecode_table =
                    Self::gen_bytecode_witness(account.address, machine_code.to_vec(), code_hash);
                // add to poseidon rows
                if machine_code.len() > 0 {
                    let unrolled_inputs =
                        get_hash_input_from_u8s_default::<Fr>(machine_code.iter().copied());
                    let mut poseidon_rows = get_poseidon_row_from_stream_input(
                        &unrolled_inputs,
                        Some(code_hash),
                        machine_code.len() as u64,
                        HASH_BLOCK_STEP_SIZE,
                    );
                    self.poseidon.append(&mut poseidon_rows);
                }
                self.bytecode.append(&mut bytecode_table);

                bytecode_set.insert((account.address, code_hash));
            }
        }
    }

    /// Generate begin padding of a witness of one block
    fn insert_begin_padding(&mut self) {
        // padding zero in the front
        (0..CoreCircuit::<Fr, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::unusable_rows().0)
            .for_each(|_| self.core.insert(0, Default::default()));
        (0..BytecodeCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.bytecode.insert(0, Default::default()));
        (0..PublicCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.public.insert(0, Default::default()));
        (0..StateCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.state.insert(0, Default::default()));
        (0..CopyCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.copy.insert(0, Default::default()));
        (0..BitwiseCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.bitwise.insert(0, Default::default()));
        (0..ArithmeticCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.arithmetic.insert(0, Default::default()));
        (0..ExpCircuit::<Fr, MAX_NUM_ROW>::unusable_rows().0)
            .for_each(|_| self.exp.insert(0, Default::default()));
    }

    /// Generate end_block of a witness of one block
    fn insert_end_block(
        &mut self,
        last_step: &GethExecStep,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let end_block_gadget = execution_gadgets_map
            .get(&ExecutionState::END_BLOCK)
            .unwrap();
        self.append(end_block_gadget.gen_witness(last_step, current_state));
    }

    /// Generate end padding of a witness of one chunk
    fn insert_end_padding(
        &mut self,
        last_step: &GethExecStep,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        // padding: add END_CHUNK to the end of core and (END_PADDING will be assigned automatically)
        let end_chunk_gadget = execution_gadgets_map
            .get(&ExecutionState::END_CHUNK)
            .unwrap();
        self.append(end_chunk_gadget.gen_witness(last_step, current_state));
    }

    fn insert_begin_chunk(
        &mut self,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let begin_chunk_gadget = execution_gadgets_map
            .get(&ExecutionState::BEGIN_CHUNK)
            .unwrap();
        self.append(begin_chunk_gadget.gen_witness(&GethExecStep::default(), current_state));
    }

    fn insert_begin_block(
        &mut self,
        current_state: &mut WitnessExecHelper,
        execution_gadgets_map: &HashMap<
            ExecutionState,
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        >,
    ) {
        let begin_block_gadget = execution_gadgets_map
            .get(&ExecutionState::BEGIN_BLOCK)
            .unwrap();
        self.append(begin_block_gadget.gen_witness(&GethExecStep::default(), current_state));
    }

    /// Generate witness of one transaction's trace
    pub fn new(chunk_data: &ChunkData) -> Self {
        assert!(U256::from(usize::MAX) >= U256::from(u64::MAX), "struct Memory doesn't support evm's memory because the range of usize is smaller than that of u64");

        let execution_gadgets: Vec<
            Box<dyn ExecutionGadget<Fr, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        > = get_every_execution_gadgets!();
        let execution_gadgets_map = execution_gadgets
            .into_iter()
            .map(|gadget| (gadget.execution_state(), gadget))
            .collect();

        let mut witness = Witness::default();
        // step 1: insert all blocks related witness: bytecode and public
        witness.insert_block_related(&chunk_data);
        // step 2: insert padding to core, bytecode, state
        witness.insert_begin_padding();
        // step 3: create witness trace by trace, and append them
        let mut current_state = WitnessExecHelper::new();
        current_state.block_num_in_chunk = chunk_data.blocks.len();
        current_state.block_number_first_block = chunk_data
            .blocks
            .first()
            .unwrap()
            .eth_block
            .number
            .unwrap_or(1.into())
            .as_u64();
        current_state.chain_id = chunk_data.chain_id;

        for (hash_idx, hash) in chunk_data.history_hashes.iter().enumerate() {
            if hash.is_zero() {
                continue;
            }
            current_state.block_hash_list.insert(
                current_state.block_number_first_block + hash_idx as u64 - 1,
                hash.clone(),
            );
        }

        // insert begin chunk
        witness.insert_begin_chunk(&mut current_state, &execution_gadgets_map);

        for (i, block) in chunk_data.blocks.iter().enumerate() {
            // initialize current_state per block
            current_state.initialize_each_block();

            let block_idx = i + 1;
            // set block_idx, txs number and log number in current_state with GethData
            current_state.block_idx = block_idx;
            current_state
                .tx_num_in_block
                .insert(block_idx, block.eth_block.transactions.len());
            current_state.log_num_in_block.insert(
                block_idx,
                block.logs.iter().map(|log_data| log_data.logs.len()).sum(),
            );
            current_state.timestamp = block.eth_block.timestamp;
            current_state.coinbase = block.eth_block.author.unwrap().as_bytes().into();
            current_state.block_gaslimit = block.eth_block.gas_limit;
            current_state.basefee = block.eth_block.base_fee_per_gas.unwrap();
            current_state.prevrandao = block.eth_block.mix_hash.unwrap().as_bytes().into();

            current_state.preprocess_storage(block);

            witness.insert_begin_block(&mut current_state, &execution_gadgets_map);

            for j in 0..block.geth_traces.len() {
                // initialize current_state per tx
                current_state.initialize_each_tx();

                let tx_idx = j + 1;
                let trace_related_witness =
                    current_state.generate_trace_witness(block, tx_idx, &execution_gadgets_map);
                witness.append(trace_related_witness);
            }
            // step 4: insert END_BLOCK
            witness.insert_end_block(
                block
                    .geth_traces
                    .last()
                    .and_then(|trace| trace.struct_logs.last())
                    .unwrap_or(&GethExecStep::default()),
                &mut current_state,
                &execution_gadgets_map,
            );
        }

        // step 5: insert end chunk
        witness.insert_end_padding(
            chunk_data
                .blocks
                .last()
                .and_then(|block| {
                    block
                        .geth_traces
                        .last()
                        .and_then(|trace| trace.struct_logs.last())
                })
                .unwrap_or(&GethExecStep::default()),
            &mut current_state,
            &execution_gadgets_map,
        );

        let inputs = public::gen_public_poseidon_hash(&mut witness);

        let mut poseidon_rows = get_poseidon_row_from_stream_input(
            &inputs,
            witness.public.last().unwrap().poseidon_hash,
            (inputs.len() * PoseidonTable::INPUT_WIDTH * POSEIDON_HASH_BYTES_IN_FIELD) as u64,
            HASH_BLOCK_STEP_SIZE,
        );
        witness.poseidon.append(&mut poseidon_rows);

        witness.state.sort_by(|a, b| {
            let key_a = state_to_be_limbs(a);
            let key_b = state_to_be_limbs(b);
            key_a.cmp(&key_b)
        });
        witness
    }

    pub fn write_all_as_csv<W: Write>(&self, writer: W) {
        let mut wtr = csv::Writer::from_writer(writer);
        let max_length = itertools::max([
            self.core.len(),
            self.bytecode.len(),
            self.state.len(),
            self.public.len(),
            self.arithmetic.len(),
            self.copy.len(),
            self.bitwise.len(),
            self.exp.len(),
        ])
        .unwrap();
        for i in 0..max_length {
            let core = self.core.get(i).cloned().unwrap_or_default();
            let state = self.state.get(i).cloned().unwrap_or_default();
            let bytecode = self.bytecode.get(i).cloned().unwrap_or_default();
            let public = self.public.get(i).cloned().unwrap_or_default();
            let arithmetic = self.arithmetic.get(i).cloned().unwrap_or_default();
            let copy = self.copy.get(i).cloned().unwrap_or_default();
            let bitwise = self.bitwise.get(i).cloned().unwrap_or_default();
            let exp = self.exp.get(i).cloned().unwrap_or_default();
            wtr.serialize((
                core, state, bytecode, public, arithmetic, copy, bitwise, exp,
            ))
            .unwrap()
        }
        wtr.flush().unwrap();
    }

    pub fn write_one_as_csv<W: Write, T: Serialize>(writer: W, table: &Vec<T>) {
        let mut wtr = csv::Writer::from_writer(writer);
        table.iter().for_each(|row| {
            wtr.serialize(row).unwrap();
        });
        wtr.flush().unwrap();
    }

    pub fn print_csv(&self) {
        let mut buf = Vec::new();
        self.write_all_as_csv(&mut buf);
        let csv_string = String::from_utf8(buf).unwrap();
        println!("{}", csv_string);
    }

    fn write_one_table<W: Write, T: Serialize, S: AsRef<str>>(
        &self,
        writer: &mut W,
        table: &Vec<T>,
        title: S,
        comments: Option<Vec<&HashMap<String, String>>>,
    ) {
        if table.is_empty() {
            println!("{} is empty!", title.as_ref());
            return;
        }
        let mut buf = Vec::new();
        Self::write_one_as_csv(&mut buf, table);
        let csv_string = String::from_utf8(buf).unwrap();

        writer.write(csv2html::start("").as_ref()).unwrap();
        writer.write(csv2html::caption(title).as_ref()).unwrap();
        let column_names: Vec<&str> = csv_string
            .lines()
            .next()
            .unwrap()
            .split(',')
            .into_iter()
            .collect();
        for (i_row, line) in csv_string.lines().enumerate() {
            let vec: Vec<String> = line.split(',').into_iter().map(|x| x.to_string()).collect();
            let mut col_attrs = vec![];
            if i_row > 0 {
                comments.as_ref().map(|x| {
                    let comments = x.get(i_row - 1).unwrap();
                    for i in 0..column_names.len() {
                        let comment = comments
                            .get(&column_names[i].to_string())
                            .map(|x| format!("title=\"{}\"", x))
                            .unwrap_or_default();
                        col_attrs.push(comment);
                    }
                });
            }
            writer
                .write(csv2html::row(&vec, i_row == 0, "".into(), &col_attrs).as_ref())
                .unwrap();
        }
        writer.write(csv2html::end().as_ref()).unwrap();
    }

    pub fn write_html<W: Write>(&self, mut writer: W) {
        writer
            .write(csv2html::prologue("Witness Table").as_ref())
            .unwrap();
        self.write_one_table(
            &mut writer,
            &self.core,
            "Core",
            Some(self.core.iter().map(|x| &x.comments).collect()),
        );
        self.write_one_table(&mut writer, &self.state, "State", None);
        self.write_one_table(&mut writer, &self.bytecode, "Bytecode", None);
        self.write_one_table(
            &mut writer,
            &self.public,
            "Public",
            Some(self.public.iter().map(|x| &x.comments).collect()),
        );
        self.write_one_table(&mut writer, &self.copy, "Copy", None);
        self.write_one_table(&mut writer, &self.exp, "Exp", None);
        self.write_one_table(&mut writer, &self.bitwise, "Bitwise", None);
        self.write_one_table(&mut writer, &self.arithmetic, "Arithmetic", None);
        self.write_one_table(&mut writer, &self.poseidon, "Poseidon", None);
        writer.write(csv2html::epilogue().as_ref()).unwrap();
    }

    /// get_public_instance get instance from witness.public, return a vector of vector of F
    pub fn get_public_instance<F: Field>(&self) -> Vec<Vec<F>> {
        public_rows_to_instance(&self.public)
    }
}
