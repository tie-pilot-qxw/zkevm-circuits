pub const NUM_STATE_HI_COL: usize = 10;
pub const NUM_STATE_LO_COL: usize = 10;
pub const MAX_NUM_ROW: usize = 245;
pub const MAX_CODESIZE: usize = 200;

/// Index of vers[] column in core circuit for state stamp in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const INDEX_STATE_STAMP: usize = 0;
pub const INDEX_LOG_STAMP: usize = 2;

/// Number of versatile columns in core circuit
pub const NUM_VERS: usize = 32;

pub(crate) const LOG_NUM_STATE_TAG: usize = 4;
