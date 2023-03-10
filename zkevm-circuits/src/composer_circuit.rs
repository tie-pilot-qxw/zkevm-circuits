//! Composer circuit is a super circuit that puts all zkevm circuits together

use crate::core_circuit::CoreCircuitConfig;

pub struct ComposerCircuitConfig<F> {
    coreCircuit: CoreCircuitConfig<F>,
    // stackCircuit: C
}
