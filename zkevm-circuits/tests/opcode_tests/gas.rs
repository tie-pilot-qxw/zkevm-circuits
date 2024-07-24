use crate::test_super_circuit_short_bytecode;
use eth_types::bytecode;

#[test]
fn gas_bytecode() {
    let bytecode = bytecode! {
        GAS
        // PUSH3(21000) // Cost of the transaction
        // GASLIMIT // Gas that was given to the context
        // SUB
        // SUB // Result is the amount of gas used up to and including the GAS instruction
        STOP
    };
    test_super_circuit_short_bytecode!(bytecode);
}
