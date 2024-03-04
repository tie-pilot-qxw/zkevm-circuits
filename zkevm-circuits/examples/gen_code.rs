// To run the example, enable feature gen_code.
// Also cargo nightly is recommended.

#[cfg(feature = "gen_code")]
fn main() {
    use convert_case::{Case, Casing};
    use genco::prelude::*;
    use std::fs::File;
    use std::io::{BufWriter, Write};

    //below `let states = ` should contain the following 4
    //state_name, e.g. "Dup", "Add", "TxContext". Need to be camel case with capital first letter.
    //num_row
    //stack_pop_num
    //stack_push_num
    let states = [
        // ("Iszero", 2, 1, 1),
        // ("AndOrXor", 5, 2, 1),
        // ("Not", 2, 1, 1),
        // ("Jump", 2, 1, 0),
        // ("Jumpi", 2, 2, 0),
        // ("Jumpdest", 1, 0, 0),
        // ("PublicContext", 2, 0, 1),
        // ("TxContext", 2, 2, 1),
        // ("Memory", 3, 2, 0),
        // ("Storage", 2, 2, 0),
        // ("CallContext", 2, 0, 1),
        // ("Calldataload", 3, 1, 1),
        // ("Calldatacopy", 3, 3, 0),
        // ("Eq", 2, 2, 1),
        // ("Lt", 3, 2, 1),
        // ("Gt", 3, 2, 1),
        // ("Slt", 3, 2, 1),
        // ("Sgt", 3, 2, 1),
        // ("Byte", 4, 2, 1),
        // ("Mul", 3, 2, 1),
        // ("Sub", 3, 2, 1),
        // ("DivMod", 3, 2, 1),
        // ("Addmod", 5, 3, 1),
        // ("Mulmod", 5, 3, 1),
        // ("Keccak", 2, 2, 1),
        // ("Pop", 2, 1, 0),
        // ("Shr", 2, 2, 1),
        // ("Codecopy", 3, 3, 0),
        // ("Extcodecopy", 3, 4, 0),
        // ("Swap", 2, 2, 1),
        // ("ReturnRevert", 3, 2, 0),
        // ("Exp", 2, 2, 1),
        ("SdivSmod", 3, 2, 1),
    ];

    let path: std::path::PathBuf = [".", "zkevm-circuits", "src", "execution_bak.txt"]
        .iter()
        .collect();
    let file = File::create(path.clone()).unwrap();
    let mut execution_stream = BufWriter::new(file);
    println!();
    println!(
        "Please open {} and copy codes to execution.rs.",
        path.to_str().unwrap()
    );
    println!();
    for (state_name, num_row, stack_pop_num, stack_push_num) in states.clone() {
        assert!(
            stack_pop_num + stack_push_num <= 4,
            "exec state has >=4 stack lookups"
        );
        if stack_pop_num + stack_push_num > 0 {
            assert!(num_row >= 2, "num_row should >=2");
        }
        writeln!(
            &mut execution_stream,
            "pub mod {};",
            state_name.to_case(Case::Snake)
        )
        .unwrap();
        let path: std::path::PathBuf = [
            ".",
            "zkevm-circuits",
            "src",
            "execution",
            format!("{}.rs", state_name.to_case(Case::Snake)).as_str(),
        ]
        .iter()
        .collect();
        if path.exists() {
            println!(
                "File {} exists! Skip gen code for it.",
                path.to_str().unwrap()
            );
            continue;
        }
        let file = File::create(path).unwrap();
        let mut stream = BufWriter::new(file);
        let state_name_uppercase = state_name.to_case(Case::ScreamingSnake);
        let tokens: rust::Tokens = quote! {
        $("// Code generated - COULD HAVE BUGS!\n// This file is a generated execution gadget definition.\n")
        use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
        use crate::table::LookupEntry;
        use crate::witness::{Witness, WitnessExecHelper};
        use eth_types::{Field, GethExecStep};
        use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
        use std::marker::PhantomData;

        const NUM_ROW: usize = $num_row;

        pub struct $(state_name)Gadget<F: Field> {
            _marker: PhantomData<F>,
        }
        impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize> ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for $(state_name)Gadget<F>
        {
            fn name(&self) -> &'static str { $[str]($[const](state_name_uppercase.as_str())) }
            fn execution_state(&self) -> ExecutionState { ExecutionState::$(state_name_uppercase.as_str()) }
            fn num_row(&self) -> usize { NUM_ROW }
            fn unusable_rows(&self) -> (usize, usize) { (NUM_ROW, 1) }
            fn get_constraints(&self, config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>, meta: &mut VirtualCells<F>) -> Vec<(String, Expression<F>)> { vec![] }
            fn get_lookups(&self, config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>, meta: &mut ConstraintSystem<F>) -> Vec<(String, LookupEntry<F>)> { vec![] }
            fn gen_witness(&self, trace: &GethExecStep, current_state: &mut CurrentState) -> Witness {
                $(for i in 0..stack_pop_num =>
                    let (stack_pop_$i, _) = current_state.get_pop_stack_row_value(trace);$['\n'])
                $(for i in 0..stack_push_num =>
                    let stack_push_$i = current_state.get_push_stack_row(trace, current_state.stack_top.unwrap_or_default());$['\n'])
                $(for i in (1..num_row).rev() =>
                    let mut core_row_$i = current_state.get_core_row_without_versatile(trace, $i);$['\n'])
                $(if stack_pop_num+stack_push_num>0 =>
                    core_row_1.insert_state_lookups([$(for i in 0..stack_pop_num join (, ) => &stack_pop_$i)$(if stack_pop_num*stack_push_num>0 =>,$[' '])$(for i in 0..stack_push_num join (, ) => &stack_push_$i)]));
                let core_row_0 = ExecutionState::$(state_name_uppercase.as_str()).into_exec_state_core_row(trace,current_state, NUM_STATE_HI_COL, NUM_STATE_LO_COL);
                Witness {
                    core: vec![$(for i in (0..num_row).rev() join (, ) => core_row_$i)],
                    state: vec![$(for i in 0..stack_pop_num join (, ) => stack_pop_$i)$(if stack_pop_num*stack_push_num>0 =>,$[' '])$(for i in 0..stack_push_num join (, ) => stack_push_$i)],
                    ..Default::default()
                }
            }
        }
        pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
        ) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
            Box::new($(state_name)Gadget {
                _marker: PhantomData,
            })
        }
        #[cfg(test)]
        mod test {
            use crate::execution::test::{
                generate_execution_gadget_test_circuit, prepare_trace_step, prepare_witness_and_prover,
            };
            generate_execution_gadget_test_circuit!();
            #[test]
            fn assign_and_constraint() {
                // prepare a state to generate witness
                let stack = Stack::from_slice(&[$(for i in 0..stack_pop_num join(, ) => $i.into())]);
                let stack_pointer = stack.0.len();
                let mut current_state = CurrentState {
                    stack_pointer,
                    stack_top: $(if stack_push_num == 0 {None} else {Some(0xff.into())}),
                    ..CurrentState::new()
                };
                // prepare a trace
                let trace = prepare_trace_step!(0, OpcodeId::STOP, stack);
                let padding_begin_row = |current_state| {
                    let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(trace,
                        current_state,
                        NUM_STATE_HI_COL,
                        NUM_STATE_LO_COL,
                    );
                    row[NUM_STATE_HI_COL + NUM_STATE_LO_COL + STACK_POINTER_IDX] = Some(stack_pointer.into());
                    row
                };
                let padding_end_row = |current_state| {
                    let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(trace,
                        current_state,
                        NUM_STATE_HI_COL,
                        NUM_STATE_LO_COL,
                    );
                    row.pc = 1.into();
                    row
                };
                let (witness, prover) =
                    prepare_witness_and_prover!(trace, current_state, padding_begin_row, padding_end_row);
                witness.print_csv();
                prover.assert_satisfied_par();
            }
        }
        };
        writeln!(&mut stream, "{}", tokens.to_file_string().unwrap()).unwrap();
    }
    writeln!(
        &mut execution_stream,
        "\n//Please add the following to `macro_rules! get_every_execution_gadgets`.\n"
    )
    .unwrap();
    for (state_name, _, _, _) in states {
        writeln!(
            &mut execution_stream,
            "crate::execution::{}::new(),",
            state_name.to_case(Case::Snake)
        )
        .unwrap();
    }
}

#[cfg(not(feature = "gen_code"))]
fn main() {
    println!("Please enable feature gen_code. Add `--features gen_code` to your command. Cargo nightly is recommended.");
}
