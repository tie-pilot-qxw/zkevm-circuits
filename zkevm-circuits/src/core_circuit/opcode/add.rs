use crate::core_circuit::execution::ExecutionGadget;
use eth_types::Field;
use halo2_proofs::plonk::ConstraintSystem;

// pub struct AddGadget<F> {}

// impl AddGadget {
//     fn configure() {
//         panic!("should impl ADD related constains");
//         panic!("also don't know how to add complex selector: one selector to denote all opcodes; check DynamicSelectorHalf");
//     }
//
//     fn synthesize() {}
// }

// impl<F: Field> ExecutionGadget<F> for AddGadget<F> {
//     const NAME: &'static str = "ADD";
//
//     fn configure(meta: &mut ConstraintSystem<F>) -> Self {}
// }
