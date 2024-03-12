mod add; //01
mod addmod; //08
            // mod address; //30
mod and; //16
mod byte; //1A
mod calldatacopy; //37
mod calldataload; //35
mod calldatasize; //36
mod caller; //33
mod callvalue; //34
mod codecopy; //39
mod div; //04
mod eq; //14
mod exp; //0A
mod gasprice; //3A
mod gt; //11
mod iszero; //15
mod lt; //10
mod modulo; //06
mod mul; //02
mod mulmod; //09
mod not; //19
mod or; //17
mod origin; //32
mod sgt; //13
mod sha3; //20
mod shl;
mod shr; //1C
mod slt; //12
mod stop; //00
mod sub; //03
mod xor; //18 //3A

mod basefee; //48
mod chainid; //46
mod coinbase; //41
mod dup1; //80
mod dup10; //89
mod dup11; //8A
mod dup12; //8B
mod dup13; //8C
mod dup14; //8D
mod dup15; //8E
mod dup16; //8F
mod dup2; //81
mod dup3; //82
mod dup4; //83
mod dup5; //84
mod dup6; //85
mod dup7; //86
mod dup8; //87
mod dup9; //88
mod gaslimit; //45
mod jump; //56
mod jumpdest; //5B
mod jumpi; //57
mod log0; //A0
mod log1; //A1
mod log2; //A2
mod log3; //A3
mod log4; //A4
mod mload; //51
mod mstore; //52
            // mod mstore8; //53
            // todo: mstore8 execution gadget is not finished yet.
mod number; //43
mod pop; //50
mod push1; //60
mod push10; //69
mod push11; //6A
mod push12; //6B
mod push13; //6C
mod push14; //6D
mod push15; //6E
mod push16; //6F
mod push17; //70
mod push18; //71
mod push19; //72
mod push2; //61
mod push20; //73
mod push21; //74
mod push22; //75
mod push23; //76
mod push24; //77
mod push25; //78
mod push26; //79
mod push27; //7A
mod push28; //7B
mod push29; //7C
mod push3; //62
mod push30; //7D
mod push31; //7E
mod push32; //7F
mod push4; //63
mod push5; //64
mod push6; //65
mod push7; //66
mod push8; //67
mod push9; //68
mod return_; //F2
             // mod revert; //FD
mod codesize; // 38
mod sar; // 1D
mod sdiv;
mod selfbalance; //47
mod sload; //54
mod smod;
mod sstore; //55
mod swap1; //90
mod swap10; //99
mod swap11; //9A
mod swap12; //9B
mod swap13; //9C
mod swap14; //9D
mod swap15; //9E
mod swap16; //9F
mod swap2; //91
mod swap3; //92
mod swap4; //93
mod swap5; //94
mod swap6; //95
mod swap7; //96
mod swap8; //97
mod swap9; //98
mod timestamp;

use rand::Rng;
use std::iter;

macro_rules! test_super_circuit_short_bytecode {
    ($bytecode:expr) => {{
        use halo2_proofs::dev::MockProver;
        use halo2_proofs::halo2curves::bn256::Fr;
        use zkevm_circuits::constant::{
            MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
        };
        use zkevm_circuits::super_circuit::SuperCircuit;
        use zkevm_circuits::util::{geth_data_test, log2_ceil, SubCircuit};
        use zkevm_circuits::witness::Witness;

        let machine_code = $bytecode.to_vec();
        let (trace, receipt_log) = trace_parser::trace_program_with_log(&machine_code, &[]);
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            receipt_log,
        ));

        let k = log2_ceil(MAX_NUM_ROW);
        // let circuit = SuperCircuit::<Fr, 490, 480, 10, 10>::new_from_witness(&witness);
        let circuit: SuperCircuit<
            Fr,
            MAX_NUM_ROW,
            MAX_CODESIZE,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        > = SuperCircuit::new_from_witness(&witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        let file_name = std::path::Path::new(file!()).file_stem().unwrap();
        let file_path = std::path::Path::new("./test_data/tmp.html")
            .with_file_name(file_name)
            .with_extension("html");
        if prover.verify_par().is_err() {
            let mut buf = std::io::BufWriter::new(std::fs::File::create(file_path).unwrap());
            witness.write_html(&mut buf);
            prover.assert_satisfied_par();
        }
        (witness, k, circuit, prover)
    }};
    ($bytecode:expr,$calldata:expr) => {{
        let calldata = hex::decode($calldata).expect("calldata should be hex string");
        use halo2_proofs::dev::MockProver;
        use halo2_proofs::halo2curves::bn256::Fr;
        use zkevm_circuits::constant::{
            MAX_CODESIZE, MAX_NUM_ROW, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
        };
        use zkevm_circuits::super_circuit::SuperCircuit;
        use zkevm_circuits::util::{geth_data_test, log2_ceil, SubCircuit};
        use zkevm_circuits::witness::Witness;

        let machine_code = $bytecode.to_vec();
        let trace = trace_parser::trace_program(&machine_code, &calldata);
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &calldata,
            false,
            Default::default(),
        ));

        let k = log2_ceil(MAX_NUM_ROW);
        // let circuit = SuperCircuit::<Fr, 490, 480, 10, 10>::new_from_witness(&witness);
        let circuit: SuperCircuit<
            Fr,
            MAX_NUM_ROW,
            MAX_CODESIZE,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        > = SuperCircuit::new_from_witness(&witness);
        let instance = circuit.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        if prover.verify_par().is_err() {
            let file_name = std::path::Path::new(file!()).file_stem().unwrap();
            let file_path = std::path::Path::new("./test_data/tmp.html")
                .with_file_name(file_name)
                .with_extension("html");
            let mut buf = std::io::BufWriter::new(std::fs::File::create(file_path).unwrap());
            witness.write_html(&mut buf);
            prover.assert_satisfied_par();
        }
        (witness, k, circuit, prover)
    }};
}
pub(self) use test_super_circuit_short_bytecode;

/// Generate random hex strings
pub fn gen_random_hex_str(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    let rstr: String = iter::repeat_with(one_char).take(len).collect();
    let prefix: String = "0x".into();
    format!("{prefix}{rstr}")
}

/// Convert trueform negtive integer to two's component representation
fn trueform_hex_str_to_twoscomponent(str: String) -> String {
    let mut inv_str: String = String::with_capacity(str.len());
    // inverse str except the first bit
    let first_char = u8::from_str_radix(&str.chars().nth(0).unwrap().to_string(), 16).unwrap();
    let inv_first_char_except_first_bit = 15 - first_char + 8;
    inv_str.push_str(&format!("{:X}", inv_first_char_except_first_bit));
    for hex_char in str.chars().skip(1) {
        let hex_value = u8::from_str_radix(&hex_char.to_string(), 16).unwrap();
        let inv = 15 - hex_value;
        let inv_char = format!("{:X}", inv);
        inv_str.push_str(&inv_char);
    }
    // add one to the inversed str
    let mut result: String = String::with_capacity(str.len());
    let mut carry = 1;
    for hex_char in inv_str.chars().rev() {
        let hex_value = u8::from_str_radix(&hex_char.to_string(), 16).unwrap();
        let sum = hex_value + carry;
        carry = sum >> 4;
        result.push_str(&format!("{:X}", sum & 0xF));
    }
    if carry != 0 {
        result.push_str(&format!("{:X}", carry));
    }
    result.chars().rev().collect()
}

/// Generate two's component representation of random positive integers
pub fn gen_random_pos_int_hex_str(len: usize) -> String {
    const FIRST_CHARSET: &[u8] = b"01234567";
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::thread_rng();

    let first_char = FIRST_CHARSET[rng.gen_range(0..FIRST_CHARSET.len())] as char;

    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    let followed_chars: String = iter::repeat_with(one_char).take(len - 1).collect();

    let prefix: String = "0x".into();
    format!("{}{}{}", prefix, first_char, followed_chars)
}

/// Generate two's component representation of random negtive integers
pub fn gen_random_neg_int_hex_str(len: usize) -> String {
    const FIRST_CHARSET: &[u8] = b"89ABCDEF";
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::thread_rng();

    let first_char = FIRST_CHARSET[rng.gen_range(0..FIRST_CHARSET.len())] as char;

    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    let followed_chars: String = iter::repeat_with(one_char).take(len - 1).collect();

    let chars = format!("{first_char}{followed_chars}");

    let prefix: String = "0x".into();
    let res = trueform_hex_str_to_twoscomponent(chars.clone());
    format!("{}{}", prefix, res)
}

#[macro_export]
macro_rules! get_func_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f)
            .rsplit("::")
            .find(|&part| part != "f" && part != "{{closure}}")
            .expect("Short function name")
    }};
}
