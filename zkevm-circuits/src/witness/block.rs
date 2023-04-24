use eth_types::evm_types::OpcodeId;
use trace_parser::Trace;

use std::marker::PhantomData;

pub const OPERAND_NUM: usize = 3;
pub const EXECUTION_STATE_NUM: usize = 256;

/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    pub witness_table: WitnessTable,
    _marker: PhantomData<F>,
}

impl<F> Block<F> {
    pub fn new(witness_table: WitnessTable) -> Block<F> {
        Block {
            witness_table,
            _marker: PhantomData::<F>,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SelectorColumn {
    pub q_first_step: bool,
    pub core_q_enable: bool,
    pub stack_q_enable: bool,
    pub bytecode_q_enable: bool,
}

/// WitnessTable contains all inputs in number format in rows
/// WitnessTable = WitnessColumn + SelectorColumn
#[derive(Debug, Clone, Default)]
pub struct WitnessTable {
    pub core: Vec<CoreCircuitWitness>,
    pub stack: Vec<StackCircuitWitness>,
    pub bytecode: Vec<BytecodeWitness>,
    pub selector: Vec<SelectorColumn>,
}

impl WitnessTable {
    pub fn new(machine_code: &Vec<u8>, trace: &Vec<Trace>) -> WitnessTable {
        let (core, stack) = Self::generate_core_and_stack(trace);
        let bytecode = Self::generate_bytecode_table(machine_code);
        let mut selector = vec![];
        for i in 0..std::cmp::max(stack.len(), core.len()) {
            selector.push(SelectorColumn {
                q_first_step: i == 0,
                core_q_enable: i != 0 && i < core.len() - 1,
                stack_q_enable: i != 0,
                bytecode_q_enable: i != 0 && i < bytecode.len() - 1,
            });
        }

        WitnessTable {
            core,
            stack,
            bytecode,
            selector,
        }
    }

    fn generate_core_and_stack(
        trace: &Vec<Trace>,
    ) -> (Vec<CoreCircuitWitness>, Vec<StackCircuitWitness>) {
        let mut core = vec![];
        Self::padding_core(&mut core);
        let mut stack = vec![StackCircuitWitness {
            stack_table_stamp: Some(0),
            stack_table_value: Some(0),
            stack_table_address: Some(0),
            stack_table_is_write: Some(0),
        }];
        let mut stack_stamp = 0u64;
        let mut stack_pointer = 0u64;
        for i in 0..trace.len() {
            let (core_row, mut stack_rows) = match trace[i].op {
                OpcodeId::ADD => {
                    Self::get_add_witness(&trace[i], &mut stack_stamp, &mut stack_pointer)
                }
                OpcodeId::PUSH1 => {
                    Self::get_push1_witness(&trace[i], &mut stack_stamp, &mut stack_pointer)
                }
                OpcodeId::STOP => {
                    Self::get_stop_witness(&trace[i], &mut stack_stamp, &mut stack_pointer)
                }
                _ => panic!("unimplemented opcode"),
            };
            core.push(core_row);
            stack.append(&mut stack_rows);
        }
        stack.sort_by(|a, b| {
            if a.stack_table_address == b.stack_table_address {
                return a.stack_table_stamp.cmp(&b.stack_table_stamp);
            };
            a.stack_table_address.cmp(&b.stack_table_address)
        });
        // println!("{:?}", core);
        // println!("{:?}", stack);
        Self::padding_core(&mut core);
        (core, stack)
    }

    fn padding_core(core: &mut Vec<CoreCircuitWitness>) {
        core.push(CoreCircuitWitness {
            program_counter: Some(0),
            opcode: Some(0),
            is_push: Some(0),
            stack_stamp: Some(0),
            stack_pointer: Some(0),
            operand: [Some(0); OPERAND_NUM],
            operand_stack_stamp: [Some(0); OPERAND_NUM],
            operand_stack_pointer: [Some(0); OPERAND_NUM],
            operand_stack_is_write: [Some(0); OPERAND_NUM],
            execution_state_selector: [Some(0); EXECUTION_STATE_NUM],
        });
    }

    fn generate_bytecode_table(machine_code: &Vec<u8>) -> Vec<BytecodeWitness> {
        let mut res = vec![];
        for i in 0..machine_code.len() {
            res.push(BytecodeWitness {
                bytecode_table_program_counter: Some(i as u64),
                bytecode_table_byte: Some(machine_code[i] as u64),
                bytecode_table_is_push: Some(0),
                bytecode_table_value_pushed: Some(0),
            });
        }
        let mut pc = 0;
        while (pc) < machine_code.len() {
            let opcode = OpcodeId::from(machine_code[pc]);
            let length = if opcode.is_push() {
                let push_length = opcode.as_u64() - OpcodeId::PUSH1.as_u64() + 1;
                let mut number = 0u64;
                for i in 0..push_length {
                    number = (number << 8) + machine_code[pc + 1 + i as usize] as u64;
                }
                res[pc].bytecode_table_is_push = Some(1);
                res[pc].bytecode_table_value_pushed = Some(number);
                push_length + 1
            } else {
                1
            };
            pc += length as usize;
        }
        res.push(BytecodeWitness {
            bytecode_table_program_counter: Some(0),
            bytecode_table_byte: Some(0),
            bytecode_table_is_push: Some(0),
            bytecode_table_value_pushed: Some(0),
        });
        res
    }

    fn get_add_witness(
        trace: &Trace,
        stack_stamp: &mut u64,
        stack_pointer: &mut u64,
    ) -> (CoreCircuitWitness, Vec<StackCircuitWitness>) {
        assert_eq!(
            trace.stack_tail_before[0].unwrap() + trace.stack_tail_before[1].unwrap(),
            trace.stack_tail_after[0].unwrap()
        );
        let mut core = CoreCircuitWitness {
            program_counter: Some(trace.pc),
            opcode: Some(trace.op.as_u64()),
            is_push: Some(0),
            stack_stamp: Some(*stack_stamp + 3),
            stack_pointer: Some(*stack_pointer - 1),
            operand: [
                trace.stack_tail_before[0],
                trace.stack_tail_before[1],
                trace.stack_tail_after[0],
            ],
            operand_stack_stamp: [
                Some(*stack_stamp + 1),
                Some(*stack_stamp + 2),
                Some(*stack_stamp + 3),
            ],
            operand_stack_pointer: [
                Some(*stack_pointer),
                Some(*stack_pointer - 1),
                Some(*stack_pointer - 1),
            ],
            operand_stack_is_write: [Some(0), Some(0), Some(1)],
            execution_state_selector: [Some(0); EXECUTION_STATE_NUM],
        };
        core.execution_state_selector[trace.op.as_u64() as usize] = Some(1);
        let stack = vec![
            StackCircuitWitness {
                stack_table_stamp: Some(*stack_stamp + 1),
                stack_table_value: trace.stack_tail_before[0],
                stack_table_address: Some(*stack_pointer),
                stack_table_is_write: Some(0),
            },
            StackCircuitWitness {
                stack_table_stamp: Some(*stack_stamp + 2),
                stack_table_value: trace.stack_tail_before[1],
                stack_table_address: Some(*stack_pointer - 1),
                stack_table_is_write: Some(0),
            },
            StackCircuitWitness {
                stack_table_stamp: Some(*stack_stamp + 3),
                stack_table_value: trace.stack_tail_after[0],
                stack_table_address: Some(*stack_pointer - 1),
                stack_table_is_write: Some(1),
            },
        ];
        *stack_stamp += 3;
        *stack_pointer -= 1;
        (core, stack)
    }

    fn get_push1_witness(
        trace: &Trace,
        stack_stamp: &mut u64,
        stack_pointer: &mut u64,
    ) -> (CoreCircuitWitness, Vec<StackCircuitWitness>) {
        let mut core = CoreCircuitWitness {
            program_counter: Some(trace.pc),
            opcode: Some(trace.op.as_u64()),
            is_push: Some(1),
            stack_stamp: Some(*stack_stamp + 1),
            stack_pointer: Some(*stack_pointer + 1),
            operand: [trace.stack_tail_after[0], Some(0), Some(0)],
            operand_stack_stamp: [Some(*stack_stamp + 1), Some(0), Some(0)],
            operand_stack_pointer: [Some(*stack_pointer + 1), Some(0), Some(0)],
            operand_stack_is_write: [Some(1), Some(0), Some(0)],
            execution_state_selector: [Some(0); EXECUTION_STATE_NUM],
        };
        core.execution_state_selector[trace.op.as_u64() as usize] = Some(1);
        let stack = vec![StackCircuitWitness {
            stack_table_stamp: Some(*stack_stamp + 1),
            stack_table_value: trace.stack_tail_after[0],
            stack_table_address: Some(*stack_pointer + 1),
            stack_table_is_write: Some(1),
        }];
        *stack_stamp += 1;
        *stack_pointer += 1;
        (core, stack)
    }

    fn get_stop_witness(
        trace: &Trace,
        _stack_stamp: &mut u64,
        _stack_pointer: &mut u64,
    ) -> (CoreCircuitWitness, Vec<StackCircuitWitness>) {
        let mut core = CoreCircuitWitness {
            program_counter: Some(trace.pc),
            opcode: Some(trace.op.as_u64()),
            is_push: Some(0),
            stack_stamp: Some(0),
            stack_pointer: Some(0),
            operand: [Some(0), Some(0), Some(0)],
            operand_stack_stamp: [Some(0), Some(0), Some(0)],
            operand_stack_pointer: [Some(0), Some(0), Some(0)],
            operand_stack_is_write: [Some(0), Some(0), Some(0)],
            execution_state_selector: [Some(0); EXECUTION_STATE_NUM],
        };
        core.execution_state_selector[trace.op.as_u64() as usize] = Some(1);
        (core, vec![])
    }
}

#[derive(Debug, Clone)]
pub struct CoreCircuitWitness {
    pub program_counter: Option<u64>,
    pub opcode: Option<u64>,
    pub is_push: Option<u64>,
    pub stack_stamp: Option<u64>,
    pub stack_pointer: Option<u64>,
    pub operand: [Option<u64>; OPERAND_NUM],
    pub operand_stack_stamp: [Option<u64>; OPERAND_NUM],
    pub operand_stack_pointer: [Option<u64>; OPERAND_NUM],
    pub operand_stack_is_write: [Option<u64>; OPERAND_NUM],
    pub execution_state_selector: [Option<u64>; EXECUTION_STATE_NUM],
}

impl Default for CoreCircuitWitness {
    fn default() -> Self {
        Self {
            program_counter: Default::default(),
            opcode: Default::default(),
            is_push: Default::default(),
            stack_stamp: Default::default(),
            stack_pointer: Default::default(),
            operand: Default::default(),
            operand_stack_stamp: Default::default(),
            operand_stack_pointer: Default::default(),
            operand_stack_is_write: Default::default(),
            execution_state_selector: [None; EXECUTION_STATE_NUM],
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct StackCircuitWitness {
    pub stack_table_stamp: Option<u64>,
    pub stack_table_value: Option<u64>,
    pub stack_table_address: Option<u64>,
    pub stack_table_is_write: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct BytecodeWitness {
    pub bytecode_table_program_counter: Option<u64>,
    pub bytecode_table_byte: Option<u64>,
    pub bytecode_table_is_push: Option<u64>,
    pub bytecode_table_value_pushed: Option<u64>,
}
