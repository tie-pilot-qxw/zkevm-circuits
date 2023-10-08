pub const NUM_STATE_HI_COL: usize = 10;
pub const NUM_STATE_LO_COL: usize = 10;
pub const MAX_NUM_ROW: usize = 501;
pub const MAX_CODESIZE: usize = 500;

/// Index of vers[] column in core circuit for state stamp in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const INDEX_STATE_STAMP: usize = 0;
pub const INDEX_LOG_STAMP: usize = 2;

/// Number of versatile columns in core circuit
pub const NUM_VERS: usize = 32;

pub(crate) const LOG_NUM_STATE_TAG: usize = 4;

/// The number of columns used by auxiliary
/// this+NUM_STATE_HI_COL+NUM_STATE_LO_COL should be no greater than 32
pub(crate) const NUM_AUXILIARY: usize = 7;

/// The text description for columns used by auxiliary
pub(crate) const DESCRIPTION_AUXILIARY: [&'static str; NUM_AUXILIARY] = [
    "state_stamp",
    "stack_pointer",
    "log_stamp",
    "gas_left",
    "refund",
    "memory_chunk",
    "read_only",
];

pub(crate) const ADDRESS_HI_FOR_CREATE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
];
