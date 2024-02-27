pub const NUM_STATE_HI_COL: usize = 9;
pub const NUM_STATE_LO_COL: usize = 9;
#[cfg(not(feature = "k_9"))]
pub const MAX_NUM_ROW: usize = 280000;
#[cfg(feature = "k_9")]
pub const MAX_NUM_ROW: usize = 480;
#[cfg(not(feature = "k_9"))]
pub const MAX_CODESIZE: usize = 2 * 24576;
#[cfg(feature = "k_9")]
pub const MAX_CODESIZE: usize = 470;

/// Index of vers[] column in core circuit for state stamp in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const INDEX_STATE_STAMP: usize = 0;
pub const INDEX_LOG_STAMP: usize = 2;

/// Number of versatile columns in core circuit
pub const NUM_VERS: usize = 32;

pub(crate) const LOG_NUM_STATE_TAG: usize = 4;

/// Number of tags in bitwise
pub(crate) const LOG_NUM_BITWISE_TAG: usize = 2;

pub(crate) const BIT_SHIFT_MAX_INDEX: u8 = 255;

/// The number of columns used by auxiliary
/// this+NUM_STATE_HI_COL+NUM_STATE_LO_COL should be no greater than 32
pub(crate) const NUM_AUXILIARY: usize = 7;

/// PUBLIC_NUM_VALUES values array's length
pub(crate) const PUBLIC_NUM_VALUES: usize = 4;

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

// big endian
pub(crate) const CREATE_ADDRESS_PREFIX: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// COPY_LOOKUP_COLUMN_CNT ,one copy lookup column count
pub(crate) const COPY_LOOKUP_COLUMN_CNT: usize = 11;

/// Number of tags in exp
pub(crate) const LOG_NUM_EXP_TAG: usize = 3;
