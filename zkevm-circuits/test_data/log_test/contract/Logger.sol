// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract Logger {
    event Log(string message); // LOG1
    event LogBy(address indexed sender, string message); // LOG2
    event Transfer(address indexed from, address indexed to, uint256 value); // LOG3
    event TransferBy(
        address indexed sender,
        address indexed from,
        address indexed to,
        uint256 value
    ); // LOG4

    function test_log0() public {
        assembly {
            log0(0x0, 0x4)
        }
    }

    function test_log1() public {
        emit Log("Hello World");
    }

    function test_log2() public {
        emit LogBy(msg.sender, "Hello World");
    }

    function test_log3() public {
        emit Transfer(msg.sender, msg.sender, 100);
    }

    function test_log4() public {
        emit TransferBy(msg.sender, msg.sender, msg.sender, 100);
    }

    function test_log_all() public {
        assembly {
            log0(0x0, 0x4)
        }
        emit Log("Hello World");
        emit LogBy(msg.sender, "Hello World");
        emit Transfer(msg.sender, msg.sender, 100);
        emit TransferBy(msg.sender, msg.sender, msg.sender, 100);
    }
}
