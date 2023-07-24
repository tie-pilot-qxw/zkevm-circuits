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
