use crate::execution::{ExecutionConfig, ExecutionGadget, ExecutionState};
use crate::table::LookupEntry;
use crate::witness::{CurrentState, Witness};
use eth_types::{Field,U256};
use ethers_core::k256::schnorr::signature::Keypair;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use std::marker::PhantomData;
use trace_parser::Trace;
use eth_types::evm_types::OpcodeId;

const NUM_ROW: usize = 3;
const LOAD_SIZE: usize = 32;

pub struct CalldataloadGadget<F: Field> {
    _marker: PhantomData<F>,
}

/// Calldataload read word from msg data at index idx in EVM,
/// idx in stack and will retrive data from msg.data[idx:idx+32] to stack.
/// data[idx]: 32-byte value starting from the given offset of the calldata.
/// All bytes after the end of the calldata are set to 0.
///
/// Calldataload Execution State layout is as follows
/// CONTENT means the word is retrived from msg.data,
/// where STATE means state table lookup,
/// DYNA_SELECTOR is dynamic selector of the state,
/// which uses NUM_STATE_HI_COL + NUM_STATE_LO_COL columns
/// AUX means auxiliary such as state stamp
/// +---+-------+-------+-------+----------+
/// |cnt| 8 col | 8 col | 8 col | not used |
/// +---+-------+-------+-------+----------+
/// | 2 | CONTENT  |      |       |          |
/// | 1 | STATE | STATE | STATE |          |
/// | 0 | DYNA_SELECTOR   | AUX            |
/// +---+-------+-------+-------+----------+
impl<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>
    ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL> for CalldataloadGadget<F>
{
    fn name(&self) -> &'static str {
        "CALLDATALOAD"
    }
    fn execution_state(&self) -> ExecutionState {
        ExecutionState::CALLDATALOAD
    }
    fn num_row(&self) -> usize {
        NUM_ROW
    }
    fn unusable_rows(&self) -> (usize, usize) {
        (NUM_ROW, 1)
    }
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)> {
        vec![]
    }
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)> {
        vec![]
    }
    fn gen_witness(&self, trace: &Trace, current_state: &mut CurrentState) -> Witness {
        assert_eq!(trace.op, OpcodeId::CALLDATALOAD);

        // pop index from stack to point msg.call_data
        let (stack_pop_0, index) = current_state.get_pop_stack_row_value();
        // load value from msg.call_data with index
        let call_data = &current_state.call_data[&current_state.call_id];
        let len = call_data.len() ;
        let mut data:Vec<u8> = vec![];
        data.extend(&call_data[index.as_usize()..len]);    
        if data.len() < LOAD_SIZE{
            let  padding = vec!(0 as u8;LOAD_SIZE-data.len());
            data.extend(&mut padding[0..].iter());
        }
        // then push the retrived value to stack
        let stack_push_0 = current_state.get_push_stack_row(U256::from(&data[0..]));
        let state_rows = current_state.get_calldata_load_rows(index.as_usize());
        // generate Witness with call_data
        // Witness::new(Tag, geth_data)
        let mut core_row_2 = current_state.get_core_row_without_versatile(2);
        core_row_2.insert_state_lookups(state_rows);
        let mut core_row_1 = current_state.get_core_row_without_versatile(1);
        core_row_1.insert_state_lookups([&stack_pop_0, &stack_push_0]);
        let core_row_0 = ExecutionState::CALLDATALOAD.into_exec_state_core_row(
            current_state, 
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        );

        Witness {
            core: vec![core_row_2, core_row_1, core_row_0],
            state: vec![stack_pop_0, stack_push_0],
            ..Default::default()
        }
    }
}
pub(crate) fn new<F: Field, const NUM_STATE_HI_COL: usize, const NUM_STATE_LO_COL: usize>(
) -> Box<dyn ExecutionGadget<F, NUM_STATE_HI_COL, NUM_STATE_LO_COL>> {
    Box::new(CalldataloadGadget {
        _marker: PhantomData,
    })
}
#[cfg(test)]
mod test {
    use crate::execution::test::{
        generate_execution_gadget_test_circuit, prepare_witness_and_prover,
    };
    generate_execution_gadget_test_circuit!();
    #[test]
    fn assign_and_constraint() {
        let stack = Stack::from_slice(&[0.into()]);
        let stack_pointer = stack.0.len();
        let mut current_state = CurrentState {
            stack,
            ..CurrentState::new()
        };

        let trace = Trace {
            pc: 0,
            op: OpcodeId::STOP,
            stack_top: Some(0xff.into()),
        };
        current_state.copy_from_trace(&trace);
        let padding_begin_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
                current_state,
                NUM_STATE_HI_COL,
                NUM_STATE_LO_COL,
            );
            row.vers_21 = Some(stack_pointer.into());
            row
        };
        let padding_end_row = |current_state| {
            let mut row = ExecutionState::END_PADDING.into_exec_state_core_row(
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
