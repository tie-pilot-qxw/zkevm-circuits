mod add;

macro_rules! test_super_circuit_short_bytecode {
    ($bytecode:expr) => {{
        use halo2_proofs::dev::MockProver;
        use halo2_proofs::halo2curves::bn256::Fr;
        use zkevm_circuits::super_circuit::SuperCircuit;
        use zkevm_circuits::util::{geth_data_test, log2_ceil, SubCircuit};
        use zkevm_circuits::witness::Witness;
        let machine_code = $bytecode.to_vec();
        let trace = trace_parser::trace_program(&machine_code);
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
        (k, circuit, witness, prover)
    }};
}
pub(self) use test_super_circuit_short_bytecode;
