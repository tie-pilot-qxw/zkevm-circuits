mod add;

macro_rules! test_super_circuit_short_bytecode {
    ($bytecode:expr) => {{
        use halo2_proofs::dev::MockProver;
        use halo2_proofs::halo2curves::bn256::Fr;
        use zkevm_circuits::super_circuit::SuperCircuit;
        use zkevm_circuits::util::{geth_data_test, log2_ceil, SubCircuit};
        use zkevm_circuits::witness::Witness;
        let machine_code = $bytecode.to_vec();
        let trace = trace_parser::trace_program(&machine_code, &[]);
        let witness = Witness::new(&geth_data_test(
            trace,
            &machine_code,
            &[],
            false,
            Default::default(),
        ));

        let k = log2_ceil(501);
        let circuit = SuperCircuit::<Fr, 501, 500, 10, 10>::new_from_witness(&witness);
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

        let k = log2_ceil(501);
        let circuit = SuperCircuit::<Fr, 501, 500, 10, 10>::new_from_witness(&witness);
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

pub fn gen_random_hex_str(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    let rstr: String = iter::repeat_with(one_char).take(len).collect();
    let prefix: String = "0x".to_string();
    format!("{prefix}{rstr}")
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
