mod mutate_witness_test;

use eth_types::evm_types::OpcodeId;
use eth_types::U256;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use zkevm_circuits::constant::{NUM_STATE_HI_COL, NUM_STATE_LO_COL};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::{get_geth_data, log2_ceil, SubCircuit};
use zkevm_circuits::witness::{arithmetic, bitwise, copy, exp, public, state, Witness};

const MAX_NUM_ROW: usize = 6000;
const MAX_CODE_SIZE: usize = 5000;

const MAX_COLUMN_NUM: usize = 40; // core电路，不包括comments

const MAX_VALUE_DELTA: usize = 11;

macro_rules! mutate_common_u256_column {
    // 变异通常的u256类型的列
    ($witness:ident, $sub_circuit:ident, $row_choice: expr, $column:ident, $value_delta: expr) => {
        let origin_value = $witness.$sub_circuit[$row_choice].$column;
        let new_value = mutate_common_u256_value(origin_value, $value_delta);
        println!(
            "Mutate witness.{}[{}].{} from {:?} to {:?}",
            stringify!($sub_circuit),
            $row_choice,
            stringify!($column),
            origin_value,
            new_value
        );
        $witness.$sub_circuit[$row_choice].$column = new_value;
    };
}

macro_rules! mutate_option_u256_column {
    // 变异Option<u256>类型的列
    ($witness:ident, $sub_circuit:ident, $row_choice: expr, $column:ident, $value_delta: expr) => {
        let origin_value = $witness.$sub_circuit[$row_choice].$column;
        let new_value = mutate_option_u256_value(origin_value, $value_delta);
        println!(
            "Mutate witness.{}[{}].{} from {:?} to {:?}",
            stringify!($sub_circuit),
            $row_choice,
            stringify!($column),
            origin_value,
            new_value
        );
        $witness.$sub_circuit[$row_choice].$column = new_value;
    };
}

fn get_baseline_witness() -> Witness {
    println!("Get baseline witness: erc20 from trace");
    let witness = Witness::new(&get_geth_data(
        "test_data/erc20_test/trace/t02_a_transfer_b_200/block_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_info.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_debug_trace.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/tx_receipt.json",
        "test_data/erc20_test/trace/t02_a_transfer_b_200/bytecode.json",
    ));
    witness
}

fn gen_seed(max_row_num: usize) -> (String, usize, usize, usize) {
    println!("Generate seed: ");
    let mut rng = rand::thread_rng();
    // 随机选择bytecode、copy、core、expr、public、state、等子电路，不包括keccak子电路
    let sub_circuits: Vec<&str> =  vec![
        "bytecode",
        "copy",
        "core",
        "exp",
        "state",
        // "arithmetic",  // 所有字段修改后概率性不报错
        "bitwise",
        // "public",  // 所有字段修改后概率性不报错
    ];

    let random_sub_circuit_choice = sub_circuits[rng.gen_range(0..sub_circuits.len())];
    let random_row_choice = rng.gen_range(0..max_row_num);
    let random_column_choice = rng.gen_range(0..MAX_COLUMN_NUM);
    let random_value_delta = rng.gen_range(1..MAX_VALUE_DELTA);

    // let random_sub_circuit_choice = "core" ; // for test certain sub circuit

    println!(" sub_circuit_choice: {random_sub_circuit_choice}");
    println!(" row_choice: {random_row_choice}");
    println!(" column_choice: {random_column_choice}");
    println!(" value_delta: {random_value_delta}");
    (
        String::from(random_sub_circuit_choice),
        random_row_choice,
        random_column_choice,
        random_value_delta,
    )
}

fn mutate_witness(witness: &mut Witness) -> &Witness {
    // 变异witness
    let max_row_num = witness.core.len();
    // 生成seed: 确定随机某个子电路，随机某行，随机某列及原值要修改的delta值
    let (random_sub_circuit_choice,
        random_row_choice,
        random_column_choice,
        random_value_delta) = gen_seed(max_row_num);

    match random_sub_circuit_choice.as_str() {
        "bytecode" => mutate_bytecode(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "copy" => mutate_copy(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "core" => mutate_core(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "exp" => mutate_exp(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "state" => mutate_state(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "arithmetic" => mutate_arithmetic(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "bitwise" => mutate_bitwise(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        "public" => mutate_public(
            witness,
            random_row_choice,
            random_column_choice,
            random_value_delta,
        ),
        _ => panic!("unexpected sub circuit choice: {}", random_sub_circuit_choice),
    }
}

fn mutate_bytecode(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的bytecode子电路-某一行某一列的值
    const BYTECODE_FIELDS_NUM: usize = 7;
    let bytecode_columns = vec![
        "addr",
        "pc",
        // "bytecode",  // 已知任意行修改后不报错
        "value_hi",
        "value_lo",
        "acc_hi",
        "acc_lo",
        "cnt",
        "is_high",
    ];
    let row_choice = row_choice % witness.bytecode.len();
    let column_choice = bytecode_columns[column_choice % bytecode_columns.len()];

    match column_choice {
        "addr" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, addr, value_delta);
        }
        "pc" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, pc, value_delta);
        }
        "bytecode" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, bytecode, value_delta);
        }
        "value_hi" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, value_hi, value_delta);
        }
        "value_lo" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, value_lo, value_delta);
        }
        "acc_hi" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, acc_hi, value_delta);
        }
        "acc_lo" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, acc_lo, value_delta);
        }
        "cnt" => {
            mutate_option_u256_column!(witness, bytecode, row_choice, cnt, value_delta);
        }
        "is_high" => {
            let origin_value = witness.bytecode[row_choice].is_high;
            let new_value = mutate_option_boolean_u256_value(origin_value);
            println!(
                "Mutate witness.bytecode[{}].is_high from {:?} to = {:?}",
                row_choice, origin_value, new_value
            );
            witness.bytecode[row_choice].is_high = new_value;
        }
        _ => panic!("unexpected bytecode column choice: {}", column_choice),
    };

    witness
}

fn mutate_copy(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的copy子电路-某一行某一列的值
    let copy_columns = vec![
        "byte",
        "src_type", // 第1行变异概率性不报错
        "src_id",
        "src_pointer", // 第1行变异概率性不报错
        "src_stamp",
        "dst_type",
        "dst_id",
        "dst_pointer",
        "dst_stamp",
        "cnt",
        "len",
        "acc",
    ];
    let row_choice = row_choice % witness.copy.len();
    let column_choice = copy_columns[column_choice % copy_columns.len()];
    // 忽略copy第1行：已知第1行部分列修改后不报错
    let row_choice = if row_choice < 1 { 1 } else { row_choice };

    match column_choice {
        "byte" => {
            mutate_common_u256_column!(witness, copy, row_choice, byte, value_delta);
        }
        "src_type" => {
            let origin_value = witness.copy[row_choice].src_type;
            let new_value = mutate_copy_tag(origin_value, value_delta);
            println!(
                "Mutate witness.copy[{}].src_type from {:?} to = {:?}",
                row_choice, origin_value, new_value
            );
            witness.copy[row_choice].src_type = new_value;
        }
        "src_id" => {
            mutate_common_u256_column!(witness, copy, row_choice, src_id, value_delta);
        }
        "src_pointer" => {
            mutate_common_u256_column!(witness, copy, row_choice, src_pointer, value_delta);
        }
        "src_stamp" => {
            mutate_common_u256_column!(witness, copy, row_choice, src_stamp, value_delta);
        }
        "dst_type" => {
            let origin_value = witness.copy[row_choice].dst_type;
            let new_value = mutate_copy_tag(origin_value, value_delta);
            println!(
                "Mutate witness.copy[{}].dst_type from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.copy[row_choice].dst_type = new_value;
        }
        "dst_id" => {
            mutate_common_u256_column!(witness, copy, row_choice, dst_id, value_delta);
        }
        "dst_pointer" => {
            mutate_common_u256_column!(witness, copy, row_choice, dst_pointer, value_delta);
        }
        "dst_stamp" => {
            mutate_common_u256_column!(witness, copy, row_choice, dst_stamp, value_delta);
        }
        "cnt" => {
            mutate_common_u256_column!(witness, copy, row_choice, cnt, value_delta);
        }
        "len" => {
            mutate_common_u256_column!(witness, copy, row_choice, len, value_delta);
        }
        "acc" => {
            mutate_common_u256_column!(witness, copy, row_choice, acc, value_delta);
        }
        _ => panic!("unexpected copy column choice: {}", column_choice),
    };
    witness
}

fn mutate_core(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的core子电路-某一行某一列的值
    // 忽略：exec_state 结构体不好变异
    // 忽略：keccak_input, comments
    let core_columns = vec![
        "tx_idx",
        "call_id",
        "code_addr",
        "pc",
        "opcode",
        "cnt",
        // "vers_0", "vers_1", "vers_2", "vers_3", "vers_4", "vers_5", "vers_6", "vers_7",  // 已知：vers_0~vers_7 变异后概率性不报错
        // "vers_8", "vers_9", "vers_10", "vers_11", "vers_12", "vers_13", "vers_14", "vers_15", // 已知：vers_8~vers_15 变异后概率性不报错
        // "vers_16", "vers_17","vers_18", "vers_19","vers_20", "vers_22", "vers_22", "vers_23",  // 已知：vers_16~vers_23 变异后概率性不报错
        // "vers_24", "vers_25","vers_26", "vers_27","vers_28", "vers_29", "vers_30","vers_31", // 已知：vers_14~vers_31 变异后概率性不报错
    ];
    let row_choice = row_choice % witness.core.len();
    let column_choice = core_columns[column_choice % core_columns.len()];

    match column_choice {
        "tx_idx" => {
            mutate_common_u256_column!(witness, core, row_choice, tx_idx, value_delta);
        }
        "call_id" => {
            mutate_common_u256_column!(witness, core, row_choice, call_id, value_delta);
        }
        "code_addr" => {
            mutate_common_u256_column!(witness, core, row_choice, code_addr, value_delta);
        }
        "pc" => {
            mutate_common_u256_column!(witness, core, row_choice, pc, value_delta);
        }
        "opcode" => {
            let origin_value = witness.core[row_choice].opcode;
            let new_value = mutate_opcode(origin_value, value_delta);
            println!(
                "Mutate witness.core[{}].opcode from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.core[row_choice].opcode = new_value;
        }
        "cnt" => {
            mutate_common_u256_column!(witness, core, row_choice, cnt, value_delta);
        }
        "vers_0" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_0, value_delta);
        }
        "vers_1" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_1, value_delta);
        }
        "vers_2" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_2, value_delta);
        }
        "vers_3" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_3, value_delta);
        }
        "vers_4" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_4, value_delta);
        }
        "vers_5" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_5, value_delta);
        }
        "vers_6" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_6, value_delta);
        }
        "vers_7" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_7, value_delta);
        }
        "vers_8" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_8, value_delta);
        }
        "vers_9" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_9, value_delta);
        }
        "vers_10" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_10, value_delta);
        }
        "vers_11" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_11, value_delta);
        }
        "vers_12" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_12, value_delta);
        }
        "vers_13" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_13, value_delta);
        }
        "vers_14" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_14, value_delta);
        }
        "vers_15" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_15, value_delta);
        }
        "vers_16" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_16, value_delta);
        }
        "vers_17" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_17, value_delta);
        }
        "vers_18" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_18, value_delta);
        }
        "vers_19" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_19, value_delta);
        }
        "vers_20" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_20, value_delta);
        }
        "vers_21" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_21, value_delta);
        }
        "vers_22" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_22, value_delta);
        }
        "vers_23" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_23, value_delta);
        }
        "vers_24" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_24, value_delta);
        }
        "vers_25" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_25, value_delta);
        }
        "vers_26" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_26, value_delta);
        }
        "vers_27" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_27, value_delta);
        }
        "vers_28" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_28, value_delta);
        }
        "vers_29" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_29, value_delta);
        }
        "vers_30" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_30, value_delta);
        }
        "vers_31" => {
            mutate_option_u256_column!(witness, core, row_choice, vers_31, value_delta);
        }
        _ => panic!("unexpected core column choice: {}", column_choice),
    };
    witness
}

fn mutate_exp(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的exp子电路-某一行某一列的值
    let exp_columns = vec![
        "tag",  // 已知第1行修改后不报错
        "base_hi", // 已知第1、2行修改后不报错
        "base_lo", // 已知第1行修改后不报错
        "index_hi", // 已知第1行修改后不报错
        "index_lo", // 已知第1、2行修改后不报错
        "count", // 已知第2行修改后不报错
        "power_hi",
        "power_lo", // 已知第2行修改后不报错
    ];
    let row_choice = row_choice % witness.exp.len();

    // 忽略exp第1、2行：已知第1、2行大多列修改后不报错
    let row_choice = if row_choice < 2 { 2 % exp_columns.len() } else { row_choice };

    let column_choice = exp_columns[column_choice % exp_columns.len()];

    match column_choice {
        "tag" => {
            let origin_value = witness.exp[row_choice].tag;
            let new_value = mutate_exp_tag(origin_value, value_delta);
            println!(
                "Mutate witness.exp[{}].tag from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.exp[row_choice].tag = new_value;
        }
        "base_hi" => {
            mutate_common_u256_column!(witness, exp, row_choice, base_hi, value_delta);
        }
        "base_lo" => {
            mutate_common_u256_column!(witness, exp, row_choice, base_lo, value_delta);
        }
        "index_hi" => {
            mutate_common_u256_column!(witness, exp, row_choice, index_hi, value_delta);
        }
        "index_lo" => {
            mutate_common_u256_column!(witness, exp, row_choice, index_lo, value_delta);
        }
        "count" => {
            mutate_common_u256_column!(witness, exp, row_choice, count, value_delta);
        }
        "power_hi" => {
            mutate_common_u256_column!(witness, exp, row_choice, power_hi, value_delta);
        }
        "power_lo" => {
            mutate_common_u256_column!(witness, exp, row_choice, power_lo, value_delta);
        }
        _ => panic!("unexpected exp column choice: {}", column_choice),
    };
    witness
}

fn mutate_state(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的state子电路-某一行某一列的值
    const STATE_FIELDS_NUM: usize = 7;
    let state_columns = vec![
        "tag",
        // "stamp", // 变异stamp概率性造成提前panic: repeated state row stamp
        "value_hi",
        "value_lo", // 已知变异第1行该字段概率性无报错
        "call_id_contract_addr",
        "pointer_hi",
        "pointer_lo",
        "is_write",
        // "value_pre_hi",  // 已知变异该字段概率性无报错
        // "value_pre_lo",  // 已知变异该字段概率性无报错
        // "committed_value_hi",  // 已知变异该字段概率性无报错
        // "committed_value_lo"  // 已知变异该字段概率性无报错
    ];
    let row_choice = row_choice % witness.core.len();
    let column_choice = state_columns[column_choice % state_columns.len()];
    // 忽略state第1行：已知第1行value_lo修改后概率性不报错
    let row_choice = if row_choice < 1 { 1 } else { row_choice };

    match column_choice {
        "tag" => {
            let origin_value = witness.state[row_choice].tag;
            let new_value = mutate_state_tag(origin_value, value_delta);
            println!(
                "Mutate witness.state[{}].tag from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.state[row_choice].tag = new_value;
        }
        "stamp" => {
            mutate_option_u256_column!(witness, state, row_choice, stamp, value_delta);
        }
        "value_hi" => {
            mutate_option_u256_column!(witness, state, row_choice, value_hi, value_delta);
        }
        "value_lo" => {
            mutate_option_u256_column!(witness, state, row_choice, value_lo, value_delta);
        }
        "call_id_contract_addr" => {
            mutate_option_u256_column!(
                witness,
                state,
                row_choice,
                call_id_contract_addr,
                value_delta
            );
        }
        "pointer_hi" => {
            mutate_option_u256_column!(witness, state, row_choice, pointer_hi, value_delta);
        }
        "pointer_lo" => {
            mutate_option_u256_column!(witness, state, row_choice, pointer_lo, value_delta);
        }
        "is_write" => {
            let origin_value = witness.state[row_choice].is_write;
            let new_value = mutate_option_boolean_u256_value(origin_value);
            println!(
                "Mutate witness.state[{}].is_write from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.state[row_choice].is_write = new_value;
        }
        "value_pre_hi" => {
            mutate_option_u256_column!(witness, state, row_choice, value_pre_hi, value_delta);
        }
        "value_pre_lo" => {
            mutate_option_u256_column!(witness, state, row_choice, value_pre_lo, value_delta);
        }
        "committed_value_hi" => {
            mutate_option_u256_column!(witness, state, row_choice, committed_value_hi, value_delta);
        }
        "committed_value_lo" => {
            mutate_option_u256_column!(witness, state, row_choice, committed_value_lo, value_delta);
        }
        _ => panic!("unexpected state column choice: {}", column_choice),
    };
    witness
}

fn mutate_arithmetic(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的arithmetic子电路-某一行某一列的值
    let arithmetic_columns = vec![
        "tag",  // 修改后不报错
        "cnt", // 修改后概率性不报错
        "operand_0_hi", // 修改后概率性不报错
        "operand_0_lo", // 修改后概率性不报错
        "operand_1_hi", // 修改后概率性不报错
        "operand_1_lo", // 修改后概率性不报错
        "u16_0", // 修改后概率性不报错
        "u16_1", // 修改后概率性不报错
        "u16_2",// 修改后概率性不报错
        "u16_3",// 修改后概率性不报错
        "u16_4",// 修改后概率性不报错
        "u16_5",// 修改后概率性不报错
        "u16_6",// 修改后概率性不报错
        "u16_7", // 修改后概率性不报错
    ];
    let row_choice = row_choice % witness.arithmetic.len();
    let column_choice = arithmetic_columns[column_choice % arithmetic_columns.len()];

    match column_choice {
        "tag" => {
            let origin_value = witness.arithmetic[row_choice].tag;
            let new_value = mutate_arithmetic_tag(origin_value, value_delta);
            println!(
                "Mutate witness.arithmetic[{}].tag from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.arithmetic[row_choice].tag = new_value;
        }
        "cnt" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, cnt, value_delta);
        }
        "operand_0_hi" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, operand_0_hi, value_delta);
        }
        "operand_0_lo" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, operand_0_lo, value_delta);
        }
        "operand_1_hi" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, operand_1_hi, value_delta);
        }
        "operand_1_lo" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, operand_1_lo, value_delta);
        }
        "u16_0" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_0, value_delta);
        }
        "u16_1" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_1, value_delta);
        }
        "u16_2" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_2, value_delta);
        }
        "u16_3" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_3, value_delta);
        }
        "u16_4" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_4, value_delta);
        }
        "u16_5" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_5, value_delta);
        }
        "u16_6" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_6, value_delta);
        }
        "u16_7" => {
            mutate_common_u256_column!(witness, arithmetic, row_choice, u16_7, value_delta);
        }
        _ => panic!("unexpected arithmetic column choice: {}", column_choice),
    };
    witness
}

fn mutate_bitwise(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的bitwise子电路-某一行某一列的值
    let bitwise_columns = vec![
        "tag",
        "byte0",
        "byte1",
        "byte2",
        "acc_0",
        "acc_1",
        "acc_2",
        "sum_2",
        "cnt",
    ];
    let row_choice = row_choice % witness.bitwise.len();
    let column_choice = bitwise_columns[column_choice % bitwise_columns.len()];

    match column_choice {
        "tag" => {
            let origin_value = witness.bitwise[row_choice].tag;
            let new_value = mutate_bitwise_tag(origin_value, value_delta);
            println!(
                "Mutate witness.bitwise[{}].tag from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.bitwise[row_choice].tag = new_value;
        }
        "byte0" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, byte_0, value_delta);
        }
        "byte1" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, byte_1, value_delta);
        }
        "byte2" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, byte_2, value_delta);
        }
        "acc_0" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, acc_0, value_delta);
        }
        "acc_1" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, acc_1, value_delta);
        }
        "acc_2" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, acc_2, value_delta);
        }
        "sum_2" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, sum_2, value_delta);
        }
        "cnt" => {
            mutate_common_u256_column!(witness, bitwise, row_choice, cnt, value_delta);
        }
        _ => panic!("unexpected bitwise column choice: {}", column_choice),
    };
    witness
}

fn mutate_public(
    witness: &mut Witness,
    row_choice: usize,
    column_choice: usize,
    value_delta: usize,
) -> &Witness {
    // 变异witness的bitwise子电路-某一行某一列的值
    let public_columns = vec![
        "tag",  // 修改后不报错
        "tx_idx_or_number_diff",  // 修改后概率性不报错
        "value_0",  // 修改后概率性不报错
        "value_1",  // 修改后概率性不报错
        "value_2",  // 修改后概率性不报错
        "value_3",  // 修改后概率性不报错
    ];
    let row_choice = row_choice % witness.public.len();
    let column_choice = public_columns[column_choice % public_columns.len()];

    match column_choice {
        "tag" => {
            let origin_value = witness.public[row_choice].tag;
            let new_value = mutate_public_tag(origin_value, value_delta);
            println!(
                "Mutate witness.public[{}].tag from {:?} to {:?}",
                row_choice, origin_value, new_value
            );
            witness.public[row_choice].tag = new_value;
        }
        "tx_idx_or_number_diff" => {
            mutate_option_u256_column!(
                witness,
                public,
                row_choice,
                tx_idx_or_number_diff,
                value_delta
            );
        }
        "value_0" => {
            mutate_option_u256_column!(witness, public, row_choice, value_0, value_delta);
        }
        "value_1" => {
            mutate_option_u256_column!(witness, public, row_choice, value_1, value_delta);
        }
        "value_2" => {
            mutate_option_u256_column!(witness, public, row_choice, value_2, value_delta);
        }
        "value_3" => {
            mutate_option_u256_column!(witness, public, row_choice, value_3, value_delta);
        }
        _ => panic!("unexpected bitwise public choice: {}", column_choice),
    };
    witness
}

fn mutate_common_u256_value(origin_value: U256, value_delta: usize) -> U256 {
    // 变异常规U256值：简单在原值基础上增加一个随机值(value_delta)
    origin_value + U256::from(value_delta)
}

fn mutate_option_u256_value(origin_value: Option<U256>, value_delta: usize) -> Option<U256> {
    // 变异Option<U256>值：无值则生成U256::from(value_delta)，有值则在原值基础上增加一个value_delta
    match origin_value {
        None => Some(U256::from(value_delta)),
        Some(origin_value) => Some(origin_value + U256::from(value_delta)),
    }
}

fn mutate_boolean_u256_value(origin_value: U256) -> U256 {
    // 变异Boolean类型U256值
    match origin_value.as_usize() {
        0 => U256::from(1),
        _ => U256::from(0),
    }
}

fn mutate_option_boolean_u256_value(origin_value: Option<U256>) -> Option<U256> {
    // 变异Boolean类型Option<U256>值
    match origin_value {
        None => Some(U256::from(1)),
        Some(origin_value) => match origin_value.as_usize() {
            0 => Some(U256::from(1)),
            _ => Some(U256::from(0)),
        },
    }
}

fn mutate_copy_tag(origin_value: copy::Tag, mut value_delta: usize) -> copy::Tag {
    // 变异copy::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const COPY_TAG_NUM: usize = 8;
    if value_delta % COPY_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = (origin_value as usize + value_delta % COPY_TAG_NUM) % COPY_TAG_NUM;
    match new_value {
        0 => copy::Tag::Zero,
        1 => copy::Tag::Memory,
        2 => copy::Tag::Calldata,
        3 => copy::Tag::Returndata,
        4 => copy::Tag::PublicLog,
        5 => copy::Tag::PublicCalldata,
        6 => copy::Tag::Bytecode,
        7 => copy::Tag::Null,
        _ => unreachable!(),
    }
}

fn mutate_exp_tag(origin_value: exp::Tag, mut value_delta: usize) -> exp::Tag {
    // 变异exp::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const EXP_TAG_NUM: usize = 5;
    if value_delta % EXP_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = (origin_value as usize + value_delta % EXP_TAG_NUM) % EXP_TAG_NUM;
    match new_value {
        0 => exp::Tag::Zero,
        1 => exp::Tag::One,
        2 => exp::Tag::Square,
        3 => exp::Tag::Bit0,
        4 => exp::Tag::Bit1,
        _ => unreachable!(),
    }
}

fn mutate_state_tag(
    origin_value: Option<state::Tag>,
    mut value_delta: usize,
) -> Option<state::Tag> {
    // 变异state::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const STATE_TAG_NUM: usize = 9;
    if value_delta % STATE_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = match origin_value {
        None => value_delta % STATE_TAG_NUM,
        Some(origin_value) => (origin_value as usize + value_delta % STATE_TAG_NUM) % STATE_TAG_NUM,
    };
    match new_value {
        0 => Some(state::Tag::Memory),
        1 => Some(state::Tag::Stack),
        2 => Some(state::Tag::Storage),
        3 => Some(state::Tag::CallContext),
        4 => Some(state::Tag::CallData),
        5 => Some(state::Tag::AddrInAccessListStorage),
        6 => Some(state::Tag::SlotInAccessListStorage),
        7 => Some(state::Tag::ReturnData),
        8 => Some(state::Tag::EndPadding),
        _ => unreachable!(),
    }
}

fn mutate_arithmetic_tag(origin_value: arithmetic::Tag, mut value_delta: usize) -> arithmetic::Tag {
    // 变异arithmetic::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const ARITHMETIC_TAG_NUM: usize = 11;
    if value_delta % ARITHMETIC_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = (origin_value as usize + value_delta % ARITHMETIC_TAG_NUM) % ARITHMETIC_TAG_NUM;
    match new_value {
        0 => arithmetic::Tag::U64Overflow,
        1 => arithmetic::Tag::Add,
        2 => arithmetic::Tag::Sub,
        3 => arithmetic::Tag::Mul,
        4 => arithmetic::Tag::DivMod,
        5 => arithmetic::Tag::SltSgt,
        6 => arithmetic::Tag::SdivSmod,
        7 => arithmetic::Tag::Addmod,
        8 => arithmetic::Tag::Mulmod,
        9 => arithmetic::Tag::Length,
        10 => arithmetic::Tag::MemoryExpansion,
        _ => unreachable!(),
    }
}

fn mutate_bitwise_tag(origin_value: bitwise::Tag, mut value_delta: usize) -> bitwise::Tag {
    // 变异bitwise::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const BITWISE_TAG_NUM: usize = 3;
    if value_delta % BITWISE_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = (origin_value as usize + value_delta % BITWISE_TAG_NUM) % BITWISE_TAG_NUM;
    match new_value {
        0 => bitwise::Tag::Nil,
        1 => bitwise::Tag::And,
        2 => bitwise::Tag::Or,
        _ => unreachable!(),
    }
}

fn mutate_public_tag(origin_value: public::Tag, mut value_delta: usize) -> public::Tag {
    // 变异bitwise::Tag: 在原Tag基础上偏移一个随机值(value_delta)
    const PUBLIC_TAG_NUM: usize = 20;
    if value_delta % PUBLIC_TAG_NUM == 0 {
        value_delta = 1; // 确保tag和原tag不一致
    }
    let new_value = (origin_value as usize + value_delta % PUBLIC_TAG_NUM) % PUBLIC_TAG_NUM;
    match new_value {
        0 => public::Tag::ChainId,
        1 => public::Tag::BlockCoinbase,
        2 => public::Tag::BlockTimestamp,
        3 => public::Tag::BlockNumber,
        4 => public::Tag::BlockDifficulty,
        5 => public::Tag::BlockGasLimit,
        6 => public::Tag::BlockBaseFee,
        7 => public::Tag::BlockHash,
        8 => public::Tag::BlockTxNum,
        9 => public::Tag::BlockLogNum,
        10 => public::Tag::TxStatus,
        11 => public::Tag::TxFromValue,
        12 => public::Tag::TxToCallDataSize,
        13 => public::Tag::TxIsCreateCallDataGasCost,
        14 => public::Tag::TxGasLimit,
        15 => public::Tag::TxGasPrice,
        16 => public::Tag::TxCalldata,
        17 => public::Tag::TxLog,
        18 => public::Tag::TxLogSize,
        19 => public::Tag::CodeSize,
        _ => unreachable!(),
    }
}

fn mutate_opcode(origin_value: OpcodeId, value_delta: usize) -> OpcodeId {
    // value_delta小于origin_opcode数量
    const OPCODE_NUM: u8 = 142;
    let value_delta: u8 = u8::try_from(value_delta).unwrap() % OPCODE_NUM;
    let new_value = (origin_value.as_u8() + value_delta) % OPCODE_NUM;
    OpcodeId::from(new_value)
}

fn get_prover_from_witness(witness: &Witness) -> MockProver<Fr> {
    let circuit: SuperCircuit<Fr, MAX_NUM_ROW, MAX_CODE_SIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL> =
        SuperCircuit::new_from_witness(&witness);
    let instance = circuit.instance();
    let k = log2_ceil(SuperCircuit::<
        Fr,
        MAX_NUM_ROW,
        MAX_CODE_SIZE,
        NUM_STATE_HI_COL,
        NUM_STATE_LO_COL,
    >::num_rows(&witness));
    let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    prover
}

macro_rules! gen_fuzz_testcases {
    ( $cnt:expr ) => {
    use crate::{get_baseline_witness, get_prover_from_witness, mutate_witness};
    seq!(SN in 0..$cnt {
        #(#[test_case(SN)])*
        fn test_mutate_witness(sn: usize) {
            // step1: Get baseline witness (erc20)
            let mut witness = get_baseline_witness();
            // step2: Generate random seed: sub_circuit_choice, row_choice, column_choice, value_delta
            // step3: Mutate witness:
            //   - 3.1 Choose sub_circuit by sub_circuit_choice, eg: witness.core
            //   - 3.2 Choose row by row_choice % sub_circuit.len(), eg: witness.core[567]
            //   - 3.3 Mutate certain cell by column_choice:
            //         eg: (witness.core[567].pc += value_delta) % column_num
            let witness= mutate_witness(&mut witness);
            // step4: Get prover from witness
            let prover = get_prover_from_witness(&witness);
            // step5: Verify par and should be error
            match prover.verify_par() {
                Ok(()) => panic!("should be error"),
                Err(errs) => println!("{:?}", errs),
            }
        }
    });
    };
}

pub(self) use gen_fuzz_testcases;
pub(self) use test;
