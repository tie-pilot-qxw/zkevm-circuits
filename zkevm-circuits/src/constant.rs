pub const NUM_STATE_HI_COL: usize = 9;
pub const NUM_STATE_LO_COL: usize = 9;
#[cfg(not(feature = "k_9"))]
pub const MAX_NUM_ROW: usize = 280000;
#[cfg(feature = "k_9")]
pub const MAX_NUM_ROW: usize = 600;
#[cfg(not(feature = "k_9"))]
pub const MAX_CODESIZE: usize = 2 * 24576;
#[cfg(feature = "k_9")]
pub const MAX_CODESIZE: usize = 470;

/// Index of vers[] column in core circuit for state stamp in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const STATE_STAMP_IDX: usize = 0;
/// Index of vers[] column in core circuit for stack pointer in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const STACK_POINTER_IDX: usize = 1;
/// Index of vers[] column in core circuit for log stamp in execution gadgets
/// NUM_STATE_HI_COL + NUM_STATE_LO_COL do not count here
pub const LOG_STAMP_IDX: usize = 2;

/// gas left index, cnt == 0, gas_left = NUM_STATE_HI_COL + NUM_STATE_LO_COL + GAS_LEFT_IDX
pub(crate) const GAS_LEFT_IDX: usize = 3;

/// Number of versatile columns in core circuit
pub const NUM_VERS: usize = 32;

pub(crate) const LOG_NUM_STATE_TAG: usize = 4;

/// Number of tags in bitwise
pub(crate) const LOG_NUM_BITWISE_TAG: usize = 2;

pub(crate) const BIT_SHIFT_MAX_IDX: u8 = 255;

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

/// log selector column start
pub(crate) const LOG_SELECTOR_COLUMN_START_IDX: usize = 8;

/// exp lookup column start
pub(crate) const EXP_COLUMN_START_IDX: usize = 26;

/// bitwise lookup column start
pub(crate) const BITWISE_COLUMN_START_IDX: usize = 10;

/// bitwise lookup column width
pub(crate) const BITWISE_COLUMN_WIDTH: usize = 5;

/// state column width
pub(crate) const STATE_COLUMN_WIDTH: usize = 8;

/// storage column width
pub(crate) const STORAGE_COLUMN_WIDTH: usize = 12;

/// bytecode lookup column start
pub(crate) const BYTECODE_COLUMN_START_IDX: usize = 24;

/// arithmetic u64 overflow lookup column start
pub(crate) const U64_OVERFLOW_START_IDX: usize = 22;
/// arithmetic u64 overflow lookup column width
pub(crate) const U64_OVERFLOW_COLUMN_WIDTH: usize = 4;

/// arithmetic lookup column width
pub(crate) const ARITHMETIC_COLUMN_WIDTH: usize = 9;

/// public lookup column width
pub(crate) const PUBLIC_COLUMN_WIDTH: usize = 6;

/// public lookup column start
pub(crate) const PUBLIC_COLUMN_START_IDX: usize = 26;

/// copy lookup column start
pub(crate) const COPY_COLUMN_START_IDX: usize = 0;

/// stamp cnt lookup column start
pub(crate) const STAMP_CNT_COLUMN_START_IDX: usize = 0;

/// copy padding lookup column start
pub(crate) const COPY_PADDING_COLUMN_START_IDX: usize = 11;

/// The index of column to store 1 , if next state is end_tx;other wise set 0
///  (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const END_CALL_NEXT_IS_END_TX: usize = 3;
/// The index of column to store 1 , if next state is call5; other wise set 0
///  (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const END_CALL_NEXT_IS_CALL5: usize = 4;

/// The index of column to store 1, if next state is begin_tx_1;other wise set 0
///  (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const END_TX_NEXT_IS_BEGIN_TX1: usize = 0;
/// The index of column to store 1, if next state is end_block;other wise set 0
/// (needs to add NUM_STATE_HI_COL + NUM_STATE_LO_COL + NUM_AUXILIARY)
pub(crate) const END_TX_NEXT_IS_END_BLOCK: usize = 1;
