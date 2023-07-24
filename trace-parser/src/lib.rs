use eth_types::evm_types::OpcodeId;
use eth_types::U256;
use parse_int::parse;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

fn parse_u256(s: &str) -> Result<U256, ()> {
    if s.len() > 2 && s[..2].eq("0x") {
        U256::from_str_radix(&s[2..], 16).map_err(|_| ())
    } else {
        U256::from_str_radix(s, 16).map_err(|_| ())
    }
}

// parse assembly in file_path to machine code
pub fn assemble_file(file_path: &str) -> Vec<u8> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            panic!("Error occurs on openning {}, {}", file_path, e);
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

#[derive(Debug)]
pub struct Trace {
    pub pc: u64,
    pub op: OpcodeId,
    pub push_value: Option<U256>,
}

pub fn trace_program(machine_code: &Vec<u8>) -> Vec<Trace> {
    let cmd_string = format!("./evm --code {} --json run", hex::encode(machine_code)).to_string();
    let res = Command::new("sh")
        .arg("-c")
        .arg(cmd_string)
        .output()
        .expect("error");
    if !res.status.success() {
        panic!("Tracing machine code FAILURE")
    }
    let s = std::str::from_utf8(&res.stdout).unwrap().split('\n');

    let mut res = vec![];
    for line in s {
        let mut t: JsonResult = serde_json::from_str(line).unwrap();

        let back = t.stack.pop();
        let push_value = if let Some(a) = back {
            Some(U256::from_str_radix(&a[2..], 16).unwrap())
        } else {
            None
        };
        if res
            .last()
            .map(|x: &Trace| x.op.is_push())
            .unwrap_or_default()
        {
            res.last_mut().unwrap().push_value = push_value;
        }
        res.push(Trace {
            pc: t.pc,
            op: OpcodeId::from(t.op),
            push_value: None,
        });
        if OpcodeId::from(t.op) == OpcodeId::STOP {
            break;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn it_works() {
        let machine_code = assemble_file("debug/1.txt");
        println!("machine code: {:?}", machine_code);
        let trace = trace_program(&machine_code);
        println!("{:?}", trace);
    }
}
