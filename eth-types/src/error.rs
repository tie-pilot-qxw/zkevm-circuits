//! Error module for the eth-types crate

use crate::evm_types::OpcodeId;
use core::fmt::{Display, Formatter, Result as FmtResult};
use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

/// Error type for any BusMapping related failure.
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    SerdeError(serde_json::error::Error),
    /// Error while generating a trace.
    TracingError(String),
    /// Block is missing information about number or base_fee
    IncompleteBlock,
    /// Denotes that the byte in the bytecode does not match with any Opcode ID.
    InvalidOpcodeIdByte(u8),
    /// Error while parsing an `Instruction/Opcode`.
    OpcodeParsing(String),
    /// Error while parsing a `MemoryAddress`.
    MemAddressParsing,
    /// Error while parsing a `StackAddress`.
    StackAddressParsing,
    /// Error while trying to convert to an incorrect `OpcodeId`.
    InvalidOpConversion,
    /// Error while trying to access an invalid/empty Stack location.
    InvalidStackPointer,
    /// Error while trying to access an invalid/empty Memory location.
    InvalidMemoryPointer,
    /// Error while trying to access an invalid/empty Storage key.
    InvalidStorageKey,
    /// Error when an EvmWord is too big to be converted into a
    /// `MemoryAddress`.
    WordToMemAddr,
    /// Signature parsing error.
    Signature(libsecp256k1::Error),
}

impl From<libsecp256k1::Error> for Error {
    fn from(err: libsecp256k1::Error) -> Self {
        Error::Signature(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl StdError for Error {}

/// Error type for a failure while parsig an Ethereum Address.
#[derive(Debug)]
pub enum EthAddressParsingError {
    /// Hex string containing the Ethereum Address is not 20*2 characters
    BadLength,
    /// Hex decoding error
    Hex(hex::FromHexError),
}

/// Errors of StructLogger Result from Geth
/// 注：这里的error对应的是EVM执行后提供的报错信息，与ExecError不同
/// 类比Opcode 与 ExecutionState之间的关系，
/// 比如OutOfGas, EVM执行发生错误后，只会提示OutOfGas，而不会提示具体对应哪个Opcode
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum GethExecError {
    /// out of gas
    OutOfGas,
    /// contract creation code storage out of gas
    CodeStoreOutOfGas,
    /// max call depth exceeded
    Depth,
    /// insufficient balance for transfer
    InsufficientBalance,
    /// contract address collision
    ContractAddressCollision,
    /// execution reverted
    ExecutionReverted,
    /// max initcode size exceeded
    MaxInitCodeSizeExceeded,
    /// max code size exceeded
    MaxCodeSizeExceeded,
    /// invalid jump destination
    InvalidJump,
    /// write protection
    WriteProtection,
    /// return data out of bounds
    ReturnDataOutOfBounds,
    /// gas uint64 overflow
    GasUintOverflow,
    /// invalid code: must not begin with 0xef
    InvalidCode,
    /// nonce uint64 overflow
    NonceUintOverflow,
    /// stack underflow
    StackUnderflow {
        /// stack length
        stack_len: u64,
        /// required length
        required: u64,
    },
    /// stack limit reached
    StackOverflow {
        /// stack length
        stack_len: u64,
        /// stack limit
        limit: u64,
    },
    /// invalid opcode
    InvalidOpcode(OpcodeId),
}

impl GethExecError {
    /// Returns the error as a string constant.
    pub fn error(self) -> &'static str {
        match self {
            GethExecError::OutOfGas => "out of gas",
            GethExecError::CodeStoreOutOfGas => "contract creation code storage out of gas",
            GethExecError::Depth => "max call depth exceeded",
            GethExecError::InsufficientBalance => "insufficient balance for transfer",
            GethExecError::ContractAddressCollision => "contract address collision",
            GethExecError::ExecutionReverted => "execution reverted",
            GethExecError::MaxInitCodeSizeExceeded => "max initcode size exceeded",
            GethExecError::MaxCodeSizeExceeded => "max code size exceeded",
            GethExecError::InvalidJump => "invalid jump destination",
            GethExecError::WriteProtection => "write protection",
            GethExecError::ReturnDataOutOfBounds => "return data out of bounds",
            GethExecError::GasUintOverflow => "gas uint64 overflow",
            GethExecError::InvalidCode => "invalid code: must not begin with 0xef",
            GethExecError::NonceUintOverflow => "nonce uint64 overflow",
            GethExecError::StackUnderflow { .. } => "stack underflow",
            GethExecError::StackOverflow { .. } => "stack limit reached",
            GethExecError::InvalidOpcode(_) => "invalid opcode",
        }
    }
}

impl Display for GethExecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            GethExecError::StackUnderflow {
                stack_len,
                required,
            } => {
                write!(f, "stack underflow ({stack_len} <=> {required})")
            }
            GethExecError::StackOverflow { stack_len, limit } => {
                write!(f, "stack limit reached {stack_len} ({limit})")
            }
            GethExecError::InvalidOpcode(op) => {
                write!(f, "invalid opcode: {op}")
            }
            _ => f.write_str(self.error()),
        }
    }
}

static STACK_UNDERFLOW_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^stack underflow \((\d+) <=> (\d+)\)$").unwrap());
static STACK_OVERFLOW_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^stack limit reached (\d+) \((\d+)\)$").unwrap());
impl From<&str> for GethExecError {
    fn from(value: &str) -> Self {
        match value {
            "out of gas" => GethExecError::OutOfGas,
            "contract creation code storage out of gas" => GethExecError::CodeStoreOutOfGas,
            "max call depth exceeded" => GethExecError::Depth,
            "insufficient balance for transfer" => GethExecError::InsufficientBalance,
            "contract address collision" => GethExecError::ContractAddressCollision,
            "execution reverted" => GethExecError::ExecutionReverted,
            "max initcode size exceeded" => GethExecError::MaxInitCodeSizeExceeded,
            "max code size exceeded" => GethExecError::MaxCodeSizeExceeded,
            "invalid jump destination" => GethExecError::InvalidJump,
            "write protection" => GethExecError::WriteProtection,
            "return data out of bounds" => GethExecError::ReturnDataOutOfBounds,
            "gas uint64 overflow" => GethExecError::GasUintOverflow,
            "invalid code: must not begin with 0xef" => GethExecError::InvalidCode,
            "nonce uint64 overflow" => GethExecError::NonceUintOverflow,
            _ if value.starts_with("stack underflow") => {
                let caps = STACK_UNDERFLOW_RE.captures(value).unwrap();
                let stack_len = caps.get(1).unwrap().as_str().parse::<u64>().unwrap();
                let required = caps.get(2).unwrap().as_str().parse::<u64>().unwrap();
                GethExecError::StackUnderflow {
                    stack_len,
                    required,
                }
            }
            _ if value.starts_with("stack limit reached") => {
                let caps = STACK_OVERFLOW_RE.captures(value).unwrap();
                let stack_len = caps.get(1).unwrap().as_str().parse::<u64>().unwrap();
                let limit = caps.get(2).unwrap().as_str().parse::<u64>().unwrap();
                GethExecError::StackOverflow { stack_len, limit }
            }
            _ if value.starts_with("invalid opcode") => value
                .strip_prefix("invalid opcode: ")
                .map(|s| OpcodeId::from_str(s).unwrap())
                .map(GethExecError::InvalidOpcode)
                .unwrap(),
            _ => panic!("invalid value: {}", value),
        }
    }
}
