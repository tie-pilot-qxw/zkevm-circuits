use eth_types::evm_types::{Memory, OpcodeId, Stack, Storage};
use eth_types::{
    Block, Bytes, GethExecStep, GethExecTrace, ReceiptLog, ResultGethExecTrace, Transaction,
    WrapBlock, WrapByteCode, WrapReceiptLog, WrapTransaction, U256,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
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
        if opcode.is_push() {
            let mut push_length = opcode.as_u64() - OpcodeId::PUSH1.as_u64() + 1;
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

pub fn trace_program(bytecode: &[u8], calldata: &[u8]) -> GethExecTrace {
    let cmd_string = if calldata.is_empty() {
        format!(
            "./evm --code {} --json  --nomemory=false run",
            hex::encode(bytecode)
        )
        .to_string()
    } else {
        format!(
            "./evm --code {} --input {} --json  --nomemory=false run",
            hex::encode(bytecode),
            hex::encode(calldata)
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
            return GethExecTrace {
                gas: result.gas_used.as_u64(),
                failed: result.error.is_some(),
                return_value: result.output.to_string(),
                struct_logs,
            };
        } else {
            unreachable!("function trace_program cannot reach here")
        }
    }
    unreachable!("function trace_program cannot reach here")
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

pub fn read_bytecode_from_api_result_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let x: WrapByteCode = serde_json::from_reader(reader).unwrap();
    let mut bytecode = x.result;
    if bytecode.starts_with("0x") {
        bytecode = bytecode.split_off(2);
    }
    hex::decode(bytecode).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn trace_and_parse() {
        let bytecode = assemble_file("debug/1.txt");
        let trace = trace_program(&bytecode, &[]);
        assert_eq!(4, trace.struct_logs.len());
    }
}
