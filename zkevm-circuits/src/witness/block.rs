use std::marker::PhantomData;

/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    _marker: PhantomData<F>,
}
