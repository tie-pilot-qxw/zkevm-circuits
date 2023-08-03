pub mod add;
pub mod push;
pub mod stop;

use crate::core_circuit::CoreCircuitConfig;
use crate::table::LookupEntry;
use crate::witness::core::Row as CoreRow;
use crate::witness::Witness;
use crate::{execution::add::AddGadget, witness::CurrentState};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use trace_parser::Trace;

pub(crate) type ExecutionConfig<F> = CoreCircuitConfig<F>;

/// Execution Gadget for the configure and witness generation of an execution state
pub(crate) trait ExecutionGadget<F: Field> {
    fn name(&self) -> &'static str;
    fn execution_state(&self) -> ExecutionState;
    /// Number of rows this execution state will use in core circuit
    fn num_row(&self) -> usize;

    /// Get gate constraints for this execution state (without condition).
    /// Rotation::cur() in the constraints means the row that column config.cnt is 0
    fn get_constraints(
        &self,
        config: &ExecutionConfig<F>,
        meta: &mut VirtualCells<F>,
    ) -> Vec<(String, Expression<F>)>;

    /// Get lookups for this execution state, prepared for merging lookups among all states
    /// Rotation::cur() in the lookups means the row that column config.cnt is 0
    fn get_lookups(
        &self,
        config: &ExecutionConfig<F>,
        meta: &mut ConstraintSystem<F>,
    ) -> Vec<(String, LookupEntry<F>)>;
}

pub(crate) trait ExecutionGadgetAssociated<F: Field> {
    fn new() -> Box<dyn ExecutionGadget<F>>;

    fn gen_witness(trace: &Trace, current_state: &mut CurrentState) -> Witness;
}

pub(crate) struct ExecutionGadgets<F: Field> {
    gadgets: Vec<Box<dyn ExecutionGadget<F>>>,
}

impl<F: Field> ExecutionGadgets<F> {
    pub(crate) fn configure(config: &ExecutionConfig<F>, meta: &mut ConstraintSystem<F>) -> Self {
        let gadgets = vec![AddGadget::new()]; //TODO add more
        let mut lookups_to_merge = vec![];
        for gadget in &gadgets {
            // the constraints that all execution state requires, e.g., cnt=num_row-1 at the first row
            meta.create_gate(format!("EXECUTION_STATE_{}", gadget.name()), |meta| {
                let q_enable = meta.query_selector(config.q_enable);
                let num_row = gadget.num_row();
                let cnt_prev_state = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32));
                // cnt in first row of this state
                let cnt_first = meta.query_advice(config.cnt, Rotation(-1 * num_row as i32 + 1));
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let condition = q_enable * cnt_is_zero; //TODO dynamic selector of gadget.execution_state
                vec![
                    (
                        "prev_state_last_cnt_is_0",
                        condition.clone() * cnt_prev_state,
                    ),
                    (
                        "this_state_first_cnt_is_const",
                        condition.clone() * (cnt_first - (num_row - 1).expr()),
                    ),
                ]
            });
            // the constraints for the specific execution state, extracted from the gadget
            meta.create_gate(format!("EXECUTION_GADGET_{}", gadget.name()), |meta| {
                // constraints without condition
                let constraints = gadget.get_constraints(config, meta);
                let q_enable = meta.query_selector(config.q_enable);
                let cnt_is_zero = config.cnt_is_zero.expr_at(meta, Rotation::cur());
                let condition = q_enable * cnt_is_zero; //TODO dynamic selector of gadget.execution_state
                constraints
                    .into_iter()
                    .map(|(s, e)| (s, condition.clone() * e))
                    .collect::<Vec<(String, Expression<F>)>>()
            });
            // extract lookups
            let execution_state = gadget.execution_state();
            let mut lookups = gadget
                .get_lookups(config, meta)
                .into_iter()
                .map(|(string, lookup)| (string, lookup, execution_state))
                .collect();
            lookups_to_merge.append(&mut lookups);
        }
        // merge lookups from all gadgets
        // todo
        ExecutionGadgets { gadgets }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum ExecutionState {
    STOP,
    ADD,
    PUSH,
}

impl ExecutionState {
    pub fn to_core_row(self) -> CoreRow {
        let op = self as usize;
        assert!(op < 100);
        let mut selector_hi = [0; 10];
        selector_hi[op / 10] = 1;
        let mut selector_lo = [0; 10];
        selector_lo[op % 10] = 1;
        CoreRow {
            vers_0: Some(selector_hi[0].into()),
            vers_1: Some(selector_hi[1].into()),
            vers_2: Some(selector_hi[2].into()),
            vers_3: Some(selector_hi[3].into()),
            vers_4: Some(selector_hi[4].into()),
            vers_5: Some(selector_hi[5].into()),
            vers_6: Some(selector_hi[6].into()),
            vers_7: Some(selector_hi[7].into()),
            vers_8: Some(selector_hi[8].into()),
            vers_9: Some(selector_hi[9].into()),
            vers_10: Some(selector_lo[0].into()),
            vers_11: Some(selector_lo[1].into()),
            vers_12: Some(selector_lo[2].into()),
            vers_13: Some(selector_lo[3].into()),
            vers_14: Some(selector_lo[4].into()),
            vers_15: Some(selector_lo[5].into()),
            vers_16: Some(selector_lo[6].into()),
            vers_17: Some(selector_lo[7].into()),
            vers_18: Some(selector_lo[8].into()),
            vers_19: Some(selector_lo[9].into()),
            ..Default::default()
        }
    }
}
