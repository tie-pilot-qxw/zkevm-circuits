// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use eth_types::U256;
use serde::Serialize;
use strum_macros::{EnumIter, EnumString};
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    /// The byte value that is copied
    pub byte: U256,
    /// The source type, one of PublicCalldata, Memory, Bytecode, Calldata, Returndata
    pub src_type: Tag,
    /// The source id, block_tx_idx for PublicCalldata, contract_addr for Bytecode, call_id for Memory, Calldata, Returndata
    pub src_id: U256,
    /// The source pointer, for PublicCalldata, Bytecode, Calldata, Returndata means the index, for Memory means the address
    pub src_pointer: U256,
    /// The source stamp, state stamp for Memory, Calldata, Returndata. None for PublicCalldata and Bytecode
    pub src_stamp: U256,
    /// The destination type, one of Memory, Calldata, Returndata, PublicLog
    pub dst_type: Tag,
    /// The destination id, block_tx_idx for PublicLog, call_id for Memory, Calldata, Returndata
    pub dst_id: U256,
    /// The destination pointer, for Calldata, Returndata, PublicLog means the index, for Memory means the address
    pub dst_pointer: U256,
    /// The destination stamp, state stamp for Memory, Calldata, Returndata. As for PublicLog it means the log_stamp
    pub dst_stamp: U256,
    /// The counter for one copy operation
    pub cnt: U256,
    /// The length for one copy operation
    pub len: U256,
    /// The accumulation value of bytes for one copy operation
    pub acc: U256,
}

/// Source and destination type.
/// Destination type could only be Memory, Calldata, Returndata, PublicLog, hence it needs two bits to represent.
/// Source type needs three bits.
#[derive(Clone, Copy, Debug, Default, Serialize, EnumIter, EnumString)]
pub enum Tag {
    #[default]
    /// Zero value for padding, under which id, pointer, and stamp are default value
    Zero,
    /// Memory in state sub-circuit
    Memory,
    /// Calldata in state sub-circuit
    Calldata,
    /// Returndata in state sub-circuit
    Returndata,
    /// Log in public sub-circuit
    PublicLog,
    /// Calldata in public sub-circuit
    PublicCalldata,
    /// Bytecode in bytecode sub-circuit
    Bytecode,
    /// Null for any value in read only/write only copy, under which id, pointer, and stamp are default value.
    /// If read only copy, dst type is Null. If write only copy, src type is Null. This is usually used
    /// in load-32-byte opcodes such as MLOAD, MWRITE, or CALLDATALOAD.
    Null,
}

impl From<Tag> for usize {
    fn from(t: Tag) -> Self {
        t as usize
    }
}

impl From<Tag> for String {
    fn from(t: Tag) -> Self {
        format!("{:?}", t)
    }
}

impl Tag {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}
