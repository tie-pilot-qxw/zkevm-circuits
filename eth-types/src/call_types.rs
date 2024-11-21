// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! EVM call trace struct

use crate::evm_types::OpcodeId;
use crate::{GethExecStep, U256};
use serde::{Deserialize, Serialize};

/// The call trace returned by geth RPC debug_trace* methods.
/// using callTracer
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct GethCallTrace {
    #[serde(default)]
    calls: Vec<GethCallTrace>,
    error: Option<String>,
    #[serde(rename = "gasUsed")]
    gas_used: U256,
    #[serde(rename = "type")]
    call_type: String,
    // value: U256,
}

impl GethCallTrace {
    /// generate call_is_success vector from call_trace
    pub fn gen_call_is_success(&self) -> Vec<bool> {
        let mut call_is_success = Vec::new();
        call_is_success.push(self.error.is_none());
        for call in &self.calls {
            let mut nested_success = call.gen_call_is_success();
            call_is_success.append(&mut nested_success);
        }
        call_is_success
    }
    /// 主要是用来兼容两种情况：
    /// 1. 用debug_transaction获取的旧的trace里不携带callTrace信息，但是由于之前我们都是成功执行的trace，所以可以使用该方法直接构造成功情况下的callTrace，
    /// 如果debug_transaction获取的是一个失败的trace信息，则不应该调用此方法，因为仅通过trace信息无法获得具体错误原因，必须结合callTracer来实现；
    /// 2. 用./evm的形式，由于没有办法使用callTracer，也可以使用该方法，如果./evm模拟的是一个错误示例，同样可以使用该方法，只是此时callTrace没有任何作用，可以
    /// 仅当作一个mock值，因为./evm模拟的错误示例里，出错的step会携带error信息，此时在witness处理阶段会直接判断出错误。
    /// 更新：往callTrace里写入trace中记录的错误信息，目前用于 Tx status 的更新。
    pub fn get_call_trace_for_test(struct_logs: &Vec<GethExecStep>) -> Self {
        let root_calls = GethCallTrace {
            calls: Vec::new(),
            error: None,
            call_type: "root".to_string(), // 区别正式的type 我们测试里可以使用这种字段做区分，目前这个字段没有其他用途
            gas_used: U256::from(100),
        };

        let mut stack: Vec<GethCallTrace> = vec![root_calls];

        for step in struct_logs {
            while stack.len() > step.depth as usize {
                let finished_call = stack.pop().unwrap();
                if let Some(last) = stack.last_mut() {
                    last.calls.push(finished_call);
                }
            }
            if step.error.is_some() {
                if let Some(a) = stack.last_mut() {
                    a.error = step.error.clone();
                }
            }
            if matches!(
                step.op,
                OpcodeId::CALL
                    | OpcodeId::CALLCODE
                    | OpcodeId::DELEGATECALL
                    | OpcodeId::STATICCALL
                    | OpcodeId::CREATE
                    | OpcodeId::CREATE2
            ) {
                let new_call = GethCallTrace {
                    calls: Vec::new(),
                    error: None,
                    call_type: step.depth.to_string(),
                    gas_used: U256::from(100),
                };

                stack.push(new_call);
            }
        }

        // Unwind remaining stack
        while stack.len() > 1 {
            let finished_call = stack.pop().unwrap();
            if let Some(last) = stack.last_mut() {
                last.calls.push(finished_call);
            }
        }

        stack.pop().unwrap()
    }

    /// check GethCallTrace is empty, empty return true
    pub fn is_empty(&self) -> bool {
        self.call_type == ""
            && self.calls.len() == 0
            && self.error == None
            && self.gas_used == U256::zero()
    }
}

#[cfg(test)]
mod test {
    use crate::call_types::GethCallTrace;
    use crate::evm_types::OpcodeId;
    use crate::{GethExecStep, GethExecTrace};

    #[test]
    fn get_call_trace_from_geth_trace() {
        let trace = GethExecTrace {
            gas: 1000,
            failed: false,
            return_value: "".to_string(),
            struct_logs: vec![
                GethExecStep {
                    pc: 1,
                    depth: 1,
                    op: OpcodeId::CALL,
                    error: None,
                    ..Default::default()
                },
                GethExecStep {
                    pc: 2,
                    depth: 2,
                    op: OpcodeId::GAS,
                    error: None,
                    ..Default::default()
                },
                GethExecStep {
                    pc: 3,
                    depth: 2,
                    op: OpcodeId::CALL,
                    error: None,
                    ..Default::default()
                },
                GethExecStep {
                    pc: 4,
                    depth: 3,
                    op: OpcodeId::GASLIMIT,
                    error: None,
                    ..Default::default()
                },
                GethExecStep {
                    pc: 5,
                    depth: 1,
                    op: OpcodeId::CALL,
                    error: None,
                    ..Default::default()
                },
            ],
            call_trace: GethCallTrace::default(),
        };
        let call_trace = GethCallTrace::get_call_trace_for_test(&trace.struct_logs);
        println!("call_trace:{:?}", call_trace)
    }

    #[test]
    fn call_trace_is_success() {
        let trace = r#"{
      "from": "0x000000000000000000000000000000000000cafe",
      "gas": "0x186a0",
      "gasUsed": "0x5c5a",
      "to": "0xfefefefefefefefefefefefefefefefefefefefe",
      "input": "0x",
      "calls": [
        {
          "from": "0xfefefefefefefefefefefefefefefefefefefefe",
          "gas": "0x2710",
          "gasUsed": "0x6",
          "to": "0xffffffffffffffffffffffffffffffffffffffff",
          "input": "0x",
          "value": "0x0",
          "type": "CALL",
          "calls": [
            {
              "from": "0xfefefefefefefefefefefefefefefefefefefefe",
              "gas": "0x2710",
              "gasUsed": "0x6",
              "to": "0xffffffffffffffffffffffffffffffffffffffff",
              "input": "0x",
              "value": "0x0",
              "type": "CALL",
              "error": "out of gas"
            }
          ]
        }
      ],
      "value": "0x0",
      "type": "CALL"
    }"#;

        let call_trace: GethCallTrace = serde_json::from_str(trace).unwrap();

        let res = call_trace.gen_call_is_success();
        println!("res:{:?}", res)
    }
}
