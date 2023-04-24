use eth_types::evm_types::OpcodeId;
use parse_int::parse;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

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
                Some(s) => match parse::<u64>(s) {
                    Ok(mut n) => {
                        let mut v = vec![];
                        while push_length > 0 {
                            v.push((n & 255) as u8);
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
    pub stack_tail_before: [Option<u64>; 8],
    pub stack_tail_after: [Option<u64>; 8],
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

        let mut stack_tail_before = [None; 8];
        for i in 0..8 {
            let back = t.stack.pop();
            if let Some(a) = back {
                stack_tail_before[i] = Some(u64::from_str_radix(&a[2..], 16).unwrap());
            }
        }
        res.push(Trace {
            pc: t.pc,
            op: OpcodeId::from(t.op),
            stack_tail_before,
            stack_tail_after: [None; 8],
        });
        if OpcodeId::from(t.op) == OpcodeId::STOP {
            break;
        }
    }
    for i in (0..res.len() - 1).rev() {
        res[i].stack_tail_after = res[i + 1].stack_tail_before.clone();
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let machine_code = assemble_file("debug/1.txt");
        println!("machine code: {:?}", machine_code);
        let trace = trace_program(&machine_code);
        println!("{:?}", trace);
    }
}
