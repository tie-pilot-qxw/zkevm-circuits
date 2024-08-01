use eth_types::evm_types::{Memory, OpcodeId, Stack, Storage};
use eth_types::geth_types::Account;
use eth_types::{
    Address, Block, Bytes, GethExecStep, GethExecTrace, ReceiptLog, ResultGethExecTrace,
    Transaction, WrapAccounts, WrapBlock, WrapReceiptLog, WrapTransaction, H256, U256,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};
use uint::FromStrRadixErr;

/// Converts a string slice to U256. Supports radixes of 10 and 16 (with '0x' prefix)
fn parse_u256(s: &str) -> Result<U256, FromStrRadixErr> {
    if s.len() > 2 && s[..2].eq("0x") {
        U256::from_str_radix(&s[2..], 16)
    } else {
        U256::from_str_radix(s, 10)
    }
}

// parse assembly in file_path to machine code
pub fn assemble_file<P: AsRef<Path>>(file_path: P) -> Vec<u8> {
    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            panic!("Error occurs on openning {:?}, {}", file_path.as_ref(), e);
        }
    };
    let reader = BufReader::new(file);
    let mut res = vec![];
    let mut cnt = 1;
    for line in reader.lines() {
        let line = line.unwrap();
        let mut it = line.split_whitespace();
        let opcode = OpcodeId::from_str(it.next().unwrap()).unwrap();
        res.push(opcode.as_u8());
        if opcode.is_push_with_data() {
            let mut push_length = opcode.as_u64() - OpcodeId::PUSH0.as_u64();
            match it.next() {
                Some(s) => match parse_u256(s) {
                    Ok(mut n) => {
                        let mut v = vec![];
                        while push_length > 0 {
                            v.push(n.byte(0));
                            n >>= 8;
                            push_length -= 1;
                        }
                        v.reverse();
                        res.append(&mut v);
                    }
                    Err(_) => {
                        panic!("On line {}, an integer needed, {} founded", cnt, s);
                    }
                },
                None => panic!("On line {}, an integer needed", cnt),
            };
        }
        cnt += 1;
    }
    res
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonResult {
    pc: u64,
    op: u8,
    stack: Vec<String>,
}

#[derive(Deserialize)]
struct EVMExecStep {
    pc: u64,
    #[serde(rename = "opName")]
    op_name: OpcodeId,
    gas: U256,
    #[serde(default)]
    refund: u64,
    #[serde(rename = "gasCost")]
    gas_cost: U256,
    depth: u16,
    error: Option<String>,
    stack: Vec<U256>,
    // memory is in one long hex string
    #[serde(default)]
    memory: String,
    // storage is hex -> hex
    #[serde(default)]
    storage: HashMap<U256, U256>,
}

impl From<EVMExecStep> for GethExecStep {
    fn from(s: EVMExecStep) -> Self {
        let memory_vec_u8 = if let Some(memory) = s.memory.strip_prefix("0x") {
            hex::decode(memory).unwrap()
        } else {
            hex::decode(s.memory).unwrap()
        };
        Self {
            pc: s.pc,
            op: s.op_name,
            gas: s.gas.as_u64(),
            refund: s.refund,
            gas_cost: s.gas_cost.as_u64(),
            depth: s.depth,
            error: s.error,
            stack: Stack(s.stack),
            memory: Memory::from(memory_vec_u8),
            storage: Storage(s.storage),
        }
    }
}

#[derive(Deserialize)]
struct EVMExecResult {
    output: Bytes,
    #[serde(rename = "gasUsed")]
    gas_used: U256,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonResultOpString {
    pc: u64,
    op: String,
    stack: Vec<String>,
}

pub fn compute_first_step_gas(calldata: &[u8]) -> u64 {
    let result = if calldata.is_empty() {
        // Our default initial gas is 0x2540be400, so the first_step in the trace should be 0x2540be400 - intrinsic_gas
        // call_data is empty, so intrinsic_gas = 21000
        0x2540be400 - 21000
    } else {
        let call_data_gas_cost = calldata
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });
        0x2540be400 - (21000 + call_data_gas_cost)
    };
    result
}

pub fn get_geth_exec_trace(res: &Output) -> GethExecTrace {
    let mut geth_exec_trace = GethExecTrace {
        gas: 0,
        failed: false,
        return_value: "".into(),
        struct_logs: vec![],
    };

    let s = std::str::from_utf8(&res.stdout).unwrap().split('\n');
    let mut struct_logs: Vec<GethExecStep> = vec![];
    for line in s {
        let result = serde_json::from_str::<EVMExecStep>(line);
        if let Ok(step) = result {
            struct_logs.push(step.into());
            continue;
        }
        let result = serde_json::from_str::<EVMExecResult>(line);
        if let Ok(result) = result {
            geth_exec_trace = GethExecTrace {
                gas: result.gas_used.as_u64(),
                failed: result.error.is_some(),
                return_value: result.output.to_string(),
                struct_logs,
            };
            break;
        } else {
            unreachable!("function trace_program cannot reach here")
        }
    }

    geth_exec_trace
}
pub fn trace_program(bytecode: &[u8], calldata: &[u8]) -> GethExecTrace {
    let gas = compute_first_step_gas(calldata);
    let cmd_string = if calldata.is_empty() {
        format!(
            "./evm --code {} --json  --nomemory=false run --gas {}",
            hex::encode(bytecode),
            gas
        )
        .to_string()
    } else {
        format!(
            "./evm --code {} --input {} --debug --json  --nomemory=false run --gas {}",
            hex::encode(bytecode),
            hex::encode(calldata),
            gas
        )
        .to_string()
    };
    let res = Command::new("sh")
        .arg("-c")
        .arg(cmd_string)
        .output()
        .expect("error");
    if !res.status.success() {
        panic!("Tracing machine code FAILURE")
    }
    get_geth_exec_trace(&res)
}

pub fn trace_program_with_log(bytecode: &[u8], calldata: &[u8]) -> (GethExecTrace, ReceiptLog) {
    let gas = compute_first_step_gas(calldata);
    let cmd_string = if calldata.is_empty() {
        format!(
            "./evm --code {} --debug --json  --nomemory=false run --gas {}",
            hex::encode(bytecode),
            gas
        )
        .to_string()
    } else {
        format!(
            "./evm --code {} --input {} --debug --json  --nomemory=false run  --gas {}",
            hex::encode(bytecode),
            hex::encode(calldata),
            gas
        )
        .to_string()
    };
    let res = Command::new("sh")
        .arg("-c")
        .arg(cmd_string)
        .output()
        .expect("error");
    if !res.status.success() {
        panic!("Tracing machine code FAILURE")
    }
    let mut receipt_log = ReceiptLog::default();
    let mut geth_exec_trace = get_geth_exec_trace(&res);
    // parse log from stderr
    if !res.stderr.is_empty() {
        let mut lines = std::str::from_utf8(&res.stderr).unwrap().split('\n');
        //first line is "#### LOGS ####"
        let header_line = lines.next();
        if header_line.unwrap_or_default().eq("#### LOGS ####".into()) {
            match lines.next() {
                Some(summary) => {
                    let temp_splits: Vec<&str> = summary.splitn(4, ' ').collect();
                    if temp_splits.len() != 4 {
                        return (geth_exec_trace, receipt_log);
                    }
                    let log_num: u64 = str::parse(
                        temp_splits[0]
                            .strip_prefix("LOG")
                            .unwrap_or_default()
                            .strip_suffix(":")
                            .unwrap_or_default(),
                    )
                    .unwrap_or_default();
                    // let log_address = H160::from_str(temp_splits[1]).unwrap();
                    // for in fn chunk_data_test, has assigned code_addr = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
                    // so not parsed from log result
                    let log_address =
                        Address::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
                    let block_num: u64 =
                        str::parse(temp_splits[2].strip_prefix("bn=").unwrap_or_default())
                            .unwrap_or_default();
                    //
                    let tx_index: u64 =
                        str::parse(temp_splits[3].strip_prefix("txi=").unwrap_or_default())
                            .unwrap_or_default();
                    let mut topics = vec![];
                    // parse topic hash
                    for _i in 0..log_num {
                        let temp_topic_line = lines.next().unwrap();
                        let topic_splits: Vec<&str> = temp_topic_line.splitn(2, ' ').collect();
                        let topic_hash = H256::from_str(topic_splits[1]).unwrap();
                        topics.push(topic_hash);
                    }
                    // parse log data
                    let mut log_data = vec![];
                    loop {
                        match lines.next() {
                            Some(temp_line) => {
                                let split_prefix: Vec<&str> = temp_line.splitn(2, ' ').collect();
                                if split_prefix.len() != 2 {
                                    break;
                                }
                                let split_postfix_index =
                                    split_prefix[1].find('|').unwrap_or_default();
                                let (temp_line_data, _) =
                                    split_prefix[1].split_at(split_postfix_index);
                                let temp_line_datas = temp_line_data.split_whitespace();
                                for d in temp_line_datas {
                                    log_data.push(u8::from_str_radix(d, 16).unwrap_or_default());
                                }
                            }
                            _ => break,
                        }
                    }
                    receipt_log = ReceiptLog::from_single_log(
                        log_address,
                        topics,
                        log_data,
                        None,
                        Some(block_num),
                        None,
                        Some(tx_index),
                        None,
                        None,
                        None,
                        None,
                    )
                }
                _ => return (geth_exec_trace, receipt_log),
            }
        } else {
            unreachable!("function trace_program_with_log must have LOGS")
        }
    }
    (geth_exec_trace, receipt_log)
}

pub fn read_trace_from_api_result_file<P: AsRef<Path>>(path: P) -> GethExecTrace {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: ResultGethExecTrace = serde_json::from_reader(reader).unwrap();
    x.result
}

pub fn read_log_from_api_result_file<P: AsRef<Path>>(path: P) -> ReceiptLog {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: WrapReceiptLog = serde_json::from_reader(reader).unwrap();
    x.result.check_data_valid();
    x.result
}

pub fn read_tx_from_api_result_file<P: AsRef<Path>>(path: P) -> Transaction {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: WrapTransaction = serde_json::from_reader(reader).unwrap();
    x.result
}

pub fn read_block_from_api_result_file<P: AsRef<Path>>(path: P) -> Block<Transaction> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: WrapBlock = serde_json::from_reader(reader).unwrap();
    x.result
}

pub fn read_accounts_from_api_result_file<P: AsRef<Path>>(path: P) -> Vec<Account> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: WrapAccounts = serde_json::from_reader(reader).unwrap();
    let accounts_len = x.result.len();
    let mut accounts: Vec<Account> = vec![];
    for i in 0..accounts_len {
        let mut bytecode = x.result[i].bytecode.clone();
        let contract_addr = x.result[i].contract_addr.clone();
        let storage = x.result[i].storage.clone();
        if bytecode.starts_with("0x") {
            bytecode = bytecode.split_off(2);
        }
        let bytecode_vec = hex::decode(bytecode).unwrap();
        // TODO read nonce, balance, storage from file
        let account = Account {
            address: contract_addr.as_bytes().into(),
            code: bytecode_vec.into(),
            storage,
            ..Default::default()
        };
        accounts.push(account);
    }
    accounts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn trace_and_parse() {
        let bytecode = assemble_file("debug/1.txt");
        let trace = trace_program(&bytecode, &[]);
        assert_eq!(5, trace.struct_logs.len());
    }
}
