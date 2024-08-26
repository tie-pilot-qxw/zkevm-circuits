// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use eth_types::evm_types::OpcodeId;
use eth_types::GethExecError;

/// Out of Gas errors by opcode
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OogError {
    /// Out of Gas for opcodes which have non-zero constant gas cost
    Constant,
    /// Out of Gas for MLOAD, MSTORE, MSTORE8, which have static memory
    /// expansion gas cost
    StaticMemoryExpansion,
    /// Out of Gas for RETURN, REVERT, which have dynamic memory expansion gas
    /// cost
    DynamicMemoryExpansion,
    /// Out of Gas for CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY,
    /// which copy a specified chunk of memory
    MemoryCopy,
    /// Out of Gas for BALANCE, EXTCODESIZE, EXTCODEHASH, which possibly touch
    /// an extra account
    AccountAccess,
    /// Out of Gas for RETURN which has code storing gas cost when it's is
    /// creation
    CodeStore,
    /// Out of Gas for LOG0, LOG1, LOG2, LOG3, LOG4
    Log,
    /// Out of Gas for EXP
    Exp,
    /// Out of Gas for SHA3
    Sha3,
    /// Out of Gas for SLOAD and SSTORE
    SloadSstore,
    /// Out of Gas for CALL, CALLCODE, DELEGATECALL and STATICCALL
    Call,
    /// Out of Gas for Precompile.
    /// ecrecover/ecadd/ecmul/ecpairing/identity oog can should be handled by this.
    /// modexp oog is handled inside modexp gadget.
    /// disabled precompiles are handled by PrecompileFailedGadget.
    Precompile,
    /// Out of Gas for CREATE and CREATE2
    Create,
    /// Out of Gas for SELFDESTRUCT
    SelfDestruct,
}

/// Contract address collision errors by opcode/state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractAddressCollisionError {
    /// Contract address collision during CREATE opcode.
    Create,
    /// Contract address collision during CREATE2 opcode.
    Create2,
}

/// Depth above limit errors by opcode/state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepthError {
    /// Depth above limit during CALL/CALLCODE/DELEGATECALL/STATICCALL opcode.
    Call,
    /// Depth above limit during CREATE opcode.
    Create,
    /// Depth above limit during CREATE2 opcode.
    Create2,
}

/// Insufficient balance errors by opcode/state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsufficientBalanceError {
    /// Insufficient balance during CALL/CALLCODE opcode.
    Call,
    /// Insufficient balance during CREATE opcode.
    Create,
    /// Insufficient balance during CREATE2 opcode.
    Create2,
}

/// Nonce uint overflow errors by opcode/state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonceUintOverflowError {
    /// Nonce uint overflow during CREATE opcode.
    Create,
    /// Nonce uint overflow during CREATE2 opcode.
    Create2,
}

/// EVM Execution Error
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// Invalid Opcode
    InvalidOpcode,
    /// For opcodes who push more than pop
    StackOverflow,
    /// For opcodes which pop, DUP and SWAP, which peek deeper element directly
    StackUnderflow,
    /// Out of Gas
    OutOfGas(OogError),
    /// For SSTORE, LOG0, LOG1, LOG2, LOG3, LOG4, CREATE, CALL, CREATE2,
    /// SELFDESTRUCT
    WriteProtection,
    /// For CALL, CALLCODE, DELEGATECALL, STATICCALL
    Depth(DepthError),
    /// For CALL, CALLCODE, CREATE, CREATE2
    InsufficientBalance(InsufficientBalanceError),
    /// For CREATE, CREATE2
    ContractAddressCollision(ContractAddressCollisionError),
    /// contract must not begin with 0xef due to EIP #3541 EVM Object Format
    /// (EOF)
    InvalidCreationCode,
    /// For JUMP, JUMPI
    InvalidJump,
    /// For RETURNDATACOPY
    ReturnDataOutOfBounds,
    /// For RETURN in a CREATE, CREATE2
    CodeStoreOutOfGas,
    /// For RETURN in a CREATE, CREATE2
    MaxCodeSizeExceeded,
    /// For CALL, CALLCODE, DELEGATECALL, STATICCALL
    PrecompileFailed,
    /// For CREATE, CREATE2
    NonceUintOverflow(NonceUintOverflowError),
}

pub(crate) fn get_step_reported_error(op: &OpcodeId, error: GethExecError) -> ExecError {
    let mut exec_error = match error {
        GethExecError::OutOfGas | GethExecError::GasUintOverflow => {
            // NOTE: We report a GasUintOverflow error as an OutOfGas error
            let oog_err = match op {
                OpcodeId::MLOAD | OpcodeId::MSTORE | OpcodeId::MSTORE8 => {
                    OogError::StaticMemoryExpansion
                }
                OpcodeId::RETURN | OpcodeId::REVERT => OogError::DynamicMemoryExpansion,
                OpcodeId::CALLDATACOPY
                | OpcodeId::CODECOPY
                | OpcodeId::EXTCODECOPY
                | OpcodeId::RETURNDATACOPY => OogError::MemoryCopy,
                OpcodeId::BALANCE | OpcodeId::EXTCODESIZE | OpcodeId::EXTCODEHASH => {
                    OogError::AccountAccess
                }
                OpcodeId::LOG0
                | OpcodeId::LOG1
                | OpcodeId::LOG2
                | OpcodeId::LOG3
                | OpcodeId::LOG4 => OogError::Log,
                OpcodeId::EXP => OogError::Exp,
                OpcodeId::SHA3 => OogError::Sha3,
                OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL => OogError::Call,
                OpcodeId::SLOAD | OpcodeId::SSTORE => OogError::SloadSstore,
                OpcodeId::CREATE | OpcodeId::CREATE2 => OogError::Create,
                OpcodeId::SELFDESTRUCT => OogError::SelfDestruct,
                _ => OogError::Constant,
            };
            Some(ExecError::OutOfGas(oog_err))
        }
        GethExecError::StackOverflow { .. } => Some(ExecError::StackOverflow),
        GethExecError::StackUnderflow { .. } => Some(ExecError::StackUnderflow),
        GethExecError::WriteProtection => Some(ExecError::WriteProtection),
        _ => None,
    };

    #[cfg(feature = "evm")]
    if exec_error.is_none() {
        exec_error = handle_evm_errors(&error, op)
    }

    exec_error.expect(&format!("Error:{error} should be handled"))
}

// 兼容./evm的测试形式，这种error会携带到opcode中
fn handle_evm_errors(error: &GethExecError, op: &OpcodeId) -> Option<ExecError> {
    match error {
        GethExecError::CodeStoreOutOfGas => Some(ExecError::CodeStoreOutOfGas),
        GethExecError::Depth => {
            let depth_error = match op {
                OpcodeId::CALL => DepthError::Call,
                OpcodeId::CREATE => DepthError::Create,
                OpcodeId::CREATE2 => DepthError::Create2,
                _ => panic!("Unexpected depth error"),
            };
            Some(ExecError::Depth(depth_error))
        }
        GethExecError::InsufficientBalance => {
            let balance_error = match op {
                OpcodeId::CALL => InsufficientBalanceError::Call,
                OpcodeId::CREATE => InsufficientBalanceError::Create,
                OpcodeId::CREATE2 => InsufficientBalanceError::Create2,
                _ => panic!("Unexpected depth error"),
            };
            Some(ExecError::InsufficientBalance(balance_error))
        }
        GethExecError::ContractAddressCollision => {
            let collision_error = match op {
                OpcodeId::CREATE => ContractAddressCollisionError::Create,
                OpcodeId::CREATE2 => ContractAddressCollisionError::Create2,
                _ => panic!("Unexpected depth error"),
            };
            Some(ExecError::ContractAddressCollision(collision_error))
        }
        GethExecError::MaxCodeSizeExceeded => Some(ExecError::MaxCodeSizeExceeded),
        GethExecError::InvalidJump => Some(ExecError::InvalidJump),
        GethExecError::ReturnDataOutOfBounds => Some(ExecError::ReturnDataOutOfBounds),
        GethExecError::InvalidOpcode(_) => Some(ExecError::InvalidOpcode),
        GethExecError::NonceUintOverflow => {
            Some(ExecError::NonceUintOverflow(NonceUintOverflowError::Create))
        }
        _ => None,
    }
}
