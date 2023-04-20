use anyhow::anyhow;
use halo2curves::bn256::Fr;
use lazy_static::lazy_static;

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

/// Witness in a row, not including selectors
#[derive(Debug, Clone)]
pub struct WitnessColumn {
    program_counter: Option<u64>,
    opcode: Option<u64>,
    is_push: Option<u64>,
    stack_stamp: Option<u64>,
    stack_pointer: Option<u64>,
    operand: [Option<u64>; OPERAND_NUM],
    operand_stack_stamp: [Option<u64>; OPERAND_NUM],
    operand_stack_pointer: [Option<u64>; OPERAND_NUM],
    operand_stack_is_write: [Option<u64>; OPERAND_NUM],
    execution_state_selector: [Option<u64>; EXECUTION_STATE_NUM],
    stack_table_stamp: Option<u64>,
    stack_table_value: Option<u64>,
    stack_table_address: Option<u64>,
    stack_table_is_write: Option<u64>,
    bytecode_table_program_counter: Option<u64>,
    bytecode_table_byte: Option<u64>,
    bytecode_table_is_push: Option<u64>,
    bytecode_table_value_pushed: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SelectorColumn {
    q_first_step: bool,
    core_q_enable: bool,
    stack_q_enable: bool,
    bytecode_q_enable: bool,
}

/// WitnessTable contains all inputs in number format in rows
/// WitnessTable = WitnessColumn + SelectorColumn
#[derive(Debug, Clone, Default)]
pub struct WitnessTable {
    rows: Vec<(WitnessColumn, SelectorColumn)>,
}

impl Default for WitnessColumn {
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
            stack_table_stamp: Default::default(),
            stack_table_value: Default::default(),
            stack_table_address: Default::default(),
            stack_table_is_write: Default::default(),
            bytecode_table_program_counter: Default::default(),
            bytecode_table_byte: Default::default(),
            bytecode_table_is_push: Default::default(),
            bytecode_table_value_pushed: Default::default(),
        }
    }
}

//why define a mutable columns function?
impl WitnessColumn {
    pub fn new(v: &Vec<u64>) -> anyhow::Result<Self> {
        let mut column = Self::default();
        let mut column_v = column.columns_mut();
        if v.len() != column_v.len() {
            return Err(anyhow!(
                "length not match, length should be {}",
                column_v.len()
            ));
        }
        column_v
            .iter_mut()
            .zip(v.iter())
            .for_each(|(x, y)| **x = Some(*y));
        Ok(column)
    }

    fn columns_mut(&mut self) -> Vec<&mut Option<u64>> {
        let mut v = vec![];
        v.push(&mut self.program_counter);
        v.push(&mut self.opcode);
        v.push(&mut self.is_push);
        v.push(&mut self.stack_stamp);
        v.push(&mut self.stack_pointer);
        for x in &mut self.operand {
            v.push(x);
        }
        for x in &mut self.operand_stack_stamp {
            v.push(x);
        }
        for x in &mut self.operand_stack_pointer {
            v.push(x);
        }
        for x in &mut self.operand_stack_is_write {
            v.push(x);
        }
        for x in &mut self.execution_state_selector {
            v.push(x);
        }
        v.push(&mut self.stack_table_stamp);
        v.push(&mut self.stack_table_value);
        v.push(&mut self.stack_table_address);
        v.push(&mut self.stack_table_is_write);
        v.push(&mut self.bytecode_table_program_counter);
        v.push(&mut self.bytecode_table_byte);
        v.push(&mut self.bytecode_table_is_push);
        v.push(&mut self.bytecode_table_value_pushed);
        v
    }

    pub fn columns(&self) -> Vec<Option<u64>> {
        let mut v = vec![];
        v.push(self.program_counter);
        v.push(self.opcode);
        v.push(self.is_push);
        v.push(self.stack_stamp);
        v.push(self.stack_pointer);
        for x in &self.operand {
            v.push(*x);
        }
        for x in &self.operand_stack_stamp {
            v.push(*x);
        }
        for x in &self.operand_stack_pointer {
            v.push(*x);
        }
        for x in &self.operand_stack_is_write {
            v.push(*x);
        }
        for x in &self.execution_state_selector {
            v.push(*x);
        }
        v.push(self.stack_table_stamp);
        v.push(self.stack_table_value);
        v.push(self.stack_table_address);
        v.push(self.stack_table_is_write);
        v.push(self.bytecode_table_program_counter);
        v.push(self.bytecode_table_byte);
        v.push(self.bytecode_table_is_push);
        v.push(self.bytecode_table_value_pushed);
        v
    }

    pub fn contains_none(&self) -> bool {
        self.columns().contains(&None)
    }
}

impl SelectorColumn {
    pub fn columns(&self) -> Vec<bool> {
        let mut v = vec![];
        v.push(self.q_first_step);
        v.push(self.core_q_enable);
        v.push(self.stack_q_enable);
        v.push(self.bytecode_q_enable);
        v
    }
    fn columns_mut(&mut self) -> Vec<&mut bool> {
        let mut v = vec![];
        v.push(&mut self.q_first_step);
        v.push(&mut self.core_q_enable);
        v.push(&mut self.stack_q_enable);
        v.push(&mut self.bytecode_q_enable);
        v
    }

    pub fn enable(&mut self, col: usize) {
        self.columns_mut().get_mut(col).map(|x| **x = true);
    }
}

impl WitnessTable {
    pub fn new(table: &Vec<Vec<u64>>) -> anyhow::Result<Self> {
        let mut rows = vec![];
        for row in table {
            let row = WitnessColumn::new(row)?;
            rows.push((row, Default::default()));
        }
        Ok(Self { rows })
    }

    pub fn enable(&mut self, row: usize, col: usize) {
        self.rows.get_mut(row).map(|(_, row)| row.enable(col));
    }

    pub fn core_circuit(&self) -> Vec<(Vec<Option<u64>>, Vec<bool>)> {
        self.rows
            .iter()
            // .filter(|(x, _)| !x.contains_none())
            .map(|(witness, selector)| {
                let mut witness = witness.columns();
                witness.truncate(273);
                let mut selector = selector.columns();
                selector.truncate(2);
                (witness, selector)
            })
            .collect()
    }

    pub fn stack_circuit(&self) -> Vec<(Vec<Option<u64>>, Vec<bool>)> {
        self.rows
            .iter()
            // .filter(|(x, _)| !x.contains_none())
            .map(|(witness, selector)| {
                let mut witness = witness.columns();
                let mut witness = witness.split_off(273);
                witness.truncate(4);
                let mut selector = selector.columns();
                let mut selector = selector.split_off(2);
                selector.truncate(1);
                (witness, selector)
            })
            .collect()
    }

    pub fn bytecode_circuit(&self) -> Vec<(Vec<Option<u64>>, Vec<bool>)> {
        self.rows
            .iter()
            // .filter(|(x, _)| !x.contains_none())
            .map(|(witness, selector)| {
                let mut witness = witness.columns();
                let mut selector = selector.columns();
                (witness.split_off(277), selector.split_off(3))
            })
            .collect()
    }
}

// #[rustfmt::skip]
lazy_static! {
    pub static ref INPUT_WITNESS_TABLE: WitnessTable = {
        let selectors = vec![0; EXECUTION_STATE_NUM];

        let columns = vec![0; 281];
        let mut table = vec![columns];

        let mut columns = vec![1, 0x60, 1, 1, 1, 0x0a, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![1, 0x0a, 1, 1]);
        columns.append(&mut vec![1, 0x60, 1, 0x0a]);
        table.push(columns);

        let mut columns = vec![3, 0x60, 1, 2, 2, 0x0b, 0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![4, 0x0a, 1, 0]);
        columns.append(&mut vec![2, 0x0a, 0, 0]);
        table.push(columns);
        //modify 0x15 to 0x16 in columns[7] for test
        let mut columns = vec![
            5, 0x01, 0, 5, 1, 0x0b, 0x0a, 0x15, 3, 4, 5, 2, 1, 1, 0, 0, 1,
        ];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x01] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![5, 0x15, 1, 1]);
        columns.append(&mut vec![3, 0x60, 1, 0x0b]);
        table.push(columns);

        let mut columns = vec![6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![2, 0x0b, 2, 1]);
        columns.append(&mut vec![4, 0x0b, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![3, 0x0b, 2, 0]);
        columns.append(&mut vec![5, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![0;4]);
        columns.append(&mut vec![6, 0x00, 0, 0]);
        table.push(columns);

        // padding row
        let columns = vec![0; 281];
        table.push(columns);

        let mut witness_table = WitnessTable::new(&table).expect("input format has error");

        witness_table.enable(0, 0);
        witness_table.enable(1, 1);
        witness_table.enable(2, 1);
        witness_table.enable(3, 1);
        witness_table.enable(4, 1);
        witness_table.enable(1, 2);
        witness_table.enable(2, 2);
        witness_table.enable(3, 2);
        witness_table.enable(4, 2);
        witness_table.enable(5, 2);
        witness_table.enable(1, 3);
        witness_table.enable(2, 3);
        witness_table.enable(3, 3);
        witness_table.enable(4, 3);
        witness_table.enable(5, 3);
        witness_table.enable(6, 3);

        witness_table
    };
    pub static ref INPUT_BLOCK: Block<Fr> = {
        Block {
            witness_table: INPUT_WITNESS_TABLE.clone(),
            _marker: PhantomData::<Fr>,
        }
    };

    pub static ref INPUT_WITNESS_TABLE_SUB: WitnessTable = {
        let selectors = vec![0; EXECUTION_STATE_NUM];

        let columns = vec![0; 281];
        let mut table = vec![columns];

        let mut columns = vec![1, 0x60, 1, 1, 1, 0x01, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![1, 0x01, 1, 1]);
        columns.append(&mut vec![1, 0x60, 1, 0x01]);
        table.push(columns);

        let mut columns = vec![3, 0x60, 1, 2, 2, 0x02, 0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![4, 0x01, 1, 0]);
        columns.append(&mut vec![2, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![
            5, 0x01, 0, 5, 1, 0x02, 0x01, 0x03, 3, 4, 5, 2, 1, 1, 0, 0, 1,
        ];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x01] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![5, 0x03, 1, 1]);
        columns.append(&mut vec![3, 0x60, 1, 0x02]);
        table.push(columns);

        let mut columns = vec![6, 0x60, 1, 6, 2, 0x04, 0, 0, 6, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![8, 0x03,1, 0]);
        columns.append(&mut vec![4, 0x02, 0, 0]);
        table.push(columns);

        let mut columns = vec![8, 0x03, 0, 9, 1, 0x4, 0x03, 0x01, 7, 8, 9, 2, 1, 1, 0, 0, 1];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x03] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![9, 0x01, 1, 1]);
        columns.append(&mut vec![5, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![2, 0x02, 2, 1]);
        columns.append(&mut vec![6, 0x60, 1, 0x04]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![3, 0x02, 2, 0]);
        columns.append(&mut vec![7, 0x04, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![6,0x04,2,1]);
        columns.append(&mut vec![8, 0x03, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![7,0x04,2,0]);
        columns.append(&mut vec![9, 0x00, 0, 0]);
        table.push(columns);

        let columns = vec![0; 281];
        table.push(columns);

        let mut witness_table = WitnessTable::new(&table).expect("input format has error");

        //witness table should update
        witness_table.enable(0, 0);
        witness_table.enable(1, 1);
        witness_table.enable(2, 1);
        witness_table.enable(3, 1);
        witness_table.enable(4, 1);
        witness_table.enable(5, 1);
        witness_table.enable(6, 1);
        witness_table.enable(1, 2);
        witness_table.enable(2, 2);
        witness_table.enable(3, 2);
        witness_table.enable(4, 2);
        witness_table.enable(5, 2);
        witness_table.enable(6, 2);
        witness_table.enable(7, 2);
        witness_table.enable(8, 2);
        witness_table.enable(9, 2);
        witness_table.enable(1, 3);
        witness_table.enable(2, 3);
        witness_table.enable(3, 3);
        witness_table.enable(4, 3);
        witness_table.enable(5, 3);
        witness_table.enable(6, 3);
        witness_table.enable(7, 3);
        witness_table.enable(8, 3);
        witness_table.enable(9, 3);

        witness_table
    };

    pub static ref INPUT_BLOCK_SUB: Block<Fr> = {
        Block {
            witness_table: INPUT_WITNESS_TABLE_SUB.clone(),
            _marker: PhantomData::<Fr>,
        }
    };

    pub static ref INPUT_WITNESS_TABLE_MUL: WitnessTable = {
        let selectors = vec![0; EXECUTION_STATE_NUM];

        let columns = vec![0; 281];
        let mut table = vec![columns];

        let mut columns = vec![1, 0x60, 1, 1, 1, 0x01, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![1, 0x01, 1, 1]);
        columns.append(&mut vec![1, 0x60, 1, 0x01]);
        table.push(columns);

        let mut columns = vec![3, 0x60, 1, 2, 2, 0x02, 0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![4, 0x01, 1, 0]);
        columns.append(&mut vec![2, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![
            5, 0x01, 0, 5, 1, 0x02, 0x01, 0x03, 3, 4, 5, 2, 1, 1, 0, 0, 1,
        ];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x01] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![5, 0x03, 1, 1]);
        columns.append(&mut vec![3, 0x60, 1, 0x02]);
        table.push(columns);

        let mut columns = vec![6, 0x60, 1, 6, 2, 0x04, 0, 0, 6, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![8, 0x03, 1, 0]);
        columns.append(&mut vec![4, 0x02, 0, 0]);
        table.push(columns);

        let mut columns = vec![8, 0x02, 0, 9, 1, 0x4, 0x03, 0x0c, 7, 8, 9, 2, 1, 1, 0, 0, 1];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x02] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![9, 0x0c, 1, 1]);
        columns.append(&mut vec![5, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![2, 0x02, 2, 1]);
        columns.append(&mut vec![6, 0x60, 1, 0x04]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![3, 0x02, 2, 0]);
        columns.append(&mut vec![7, 0x04, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![6,0x04,2,1]);
        columns.append(&mut vec![8, 0x02, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![7,0x04,2,0]);
        columns.append(&mut vec![9, 0x00, 0, 0]);
        table.push(columns);

        let columns = vec![0; 281];
        table.push(columns);

        let mut witness_table = WitnessTable::new(&table).expect("input format has error");

        //witness table should update
        witness_table.enable(0, 0);
        witness_table.enable(1, 1);
        witness_table.enable(2, 1);
        witness_table.enable(3, 1);
        witness_table.enable(4, 1);
        witness_table.enable(5, 1);
        witness_table.enable(6, 1);
        witness_table.enable(1, 2);
        witness_table.enable(2, 2);
        witness_table.enable(3, 2);
        witness_table.enable(4, 2);
        witness_table.enable(5, 2);
        witness_table.enable(6, 2);
        witness_table.enable(1, 3);
        witness_table.enable(2, 3);
        witness_table.enable(3, 3);
        witness_table.enable(4, 3);
        witness_table.enable(5, 3);
        witness_table.enable(6, 3);
        witness_table.enable(7, 3);
        witness_table.enable(8, 3);
        witness_table.enable(9, 3);

        witness_table
    };

    pub static ref INPUT_BLOCK_MUL: Block<Fr> = {
        Block {
            witness_table: INPUT_WITNESS_TABLE_MUL.clone(),
            _marker: PhantomData::<Fr>,
        }
    };

    pub static ref INPUT_WITNESS_TABLE_POP: WitnessTable = {
        let selectors = vec![0; EXECUTION_STATE_NUM];

        let columns = vec![0; 281];
        let mut table = vec![columns];

        let mut columns = vec![1, 0x60, 1, 1, 1, 0x01, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![1, 0x01, 1, 1]);
        columns.append(&mut vec![1, 0x60, 1, 0x01]);
        table.push(columns);

        let mut columns = vec![3, 0x60, 1, 2, 2, 0x02, 0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![6, 0x01, 1, 0]);
        columns.append(&mut vec![2, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![
            5, 0x50, 0, 3, 1, 0x02, 0, 0, 3, 0, 0, 2, 0, 0, 0, 0, 0,
        ];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x50] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![7, 0x04, 1, 1]);
        columns.append(&mut vec![3, 0x60, 1, 0x02]);
        table.push(columns);

        let mut columns = vec![6, 0x60, 1, 4, 2, 0x03, 0, 0, 4, 0, 0, 2, 0, 0, 1, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x60] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![2, 0x02, 2, 1]);
        columns.append(&mut vec![4, 0x02, 0, 0]);
        table.push(columns);

        let mut columns = vec![8, 0x01, 0, 7, 1, 0x3, 0x01, 0x04, 5, 6, 7, 2, 1, 1, 0, 0, 1];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x01] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![3, 0x02, 2, 0]);
        columns.append(&mut vec![5, 0x50, 0, 0]);
        table.push(columns);

        let mut columns = vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![4, 0x03, 2, 1]);
        columns.append(&mut vec![6, 0x60, 1, 0x03]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        columns.append(&mut vec![5, 0x03, 2, 0]);
        columns.append(&mut vec![7, 0x03, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![0;4]);
        columns.append(&mut vec![8, 0x01, 0, 0]);
        table.push(columns);

        let mut columns = vec![0; 17];
        let mut selectors_clone = selectors.clone();
        selectors_clone[0x00] = 1;
        columns.append(&mut selectors_clone);
        //padding 0 here
        columns.append(&mut vec![0;4]);
        columns.append(&mut vec![9, 0x00, 0, 0]);
        table.push(columns);

        let columns = vec![0; 281];
        table.push(columns);

        let mut witness_table = WitnessTable::new(&table).expect("input format has error");

        //witness table should update
        witness_table.enable(0, 0);
        witness_table.enable(1, 1);
        witness_table.enable(2, 1);
        witness_table.enable(3, 1);
        witness_table.enable(4, 1);
        witness_table.enable(5, 1);
        witness_table.enable(6, 1);
        witness_table.enable(1, 2);
        witness_table.enable(2, 2);
        witness_table.enable(3, 2);
        witness_table.enable(4, 2);
        witness_table.enable(5, 2);
        witness_table.enable(6, 2);
        witness_table.enable(7, 2);
        witness_table.enable(1, 3);
        witness_table.enable(2, 3);
        witness_table.enable(3, 3);
        witness_table.enable(4, 3);
        witness_table.enable(5, 3);
        witness_table.enable(6, 3);
        witness_table.enable(7, 3);
        witness_table.enable(8, 3);
        witness_table.enable(9, 3);

        witness_table
    };

    pub static ref INPUT_BLOCK_POP: Block<Fr> = {
        Block {
            witness_table: INPUT_WITNESS_TABLE_POP.clone(),
            _marker: PhantomData::<Fr>,
        }
    };

}

#[cfg(test)]
mod test {
    use crate::witness::block::{
        INPUT_WITNESS_TABLE, INPUT_WITNESS_TABLE_MUL, INPUT_WITNESS_TABLE_POP,
        INPUT_WITNESS_TABLE_SUB,
    };

    #[test]
    fn test_lazy_static() {
        println!("{:?}", *INPUT_WITNESS_TABLE);
        println!("{:?}", INPUT_WITNESS_TABLE.core_circuit());
        println!("{:?}", INPUT_WITNESS_TABLE.bytecode_circuit());
    }

    #[test]
    fn test_lazy_static_SUB() {
        println!("{:?}", *INPUT_WITNESS_TABLE_SUB);
        println!("{:?}", INPUT_WITNESS_TABLE_SUB.core_circuit());
        println!("{:?}", INPUT_WITNESS_TABLE_SUB.bytecode_circuit());
    }

    #[test]
    fn test_lazy_static_MUL() {
        println!("{:?}", *INPUT_WITNESS_TABLE_MUL);
        println!("{:?}", INPUT_WITNESS_TABLE_MUL.core_circuit());
        println!("{:?}", INPUT_WITNESS_TABLE_MUL.bytecode_circuit());
    }

    fn test_lazy_static_POP() {
        println!("{:?}", *INPUT_WITNESS_TABLE_POP);
        println!("{:?}", INPUT_WITNESS_TABLE_POP.core_circuit());
        println!("{:?}", INPUT_WITNESS_TABLE_POP.bytecode_circuit());
    }
}
