// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract MyContract {
    address public A;
    address public B;
    address public C;
    uint256 public resultFromB;
    uint256 public counterFromC;
    uint256 public returndatasizeFromB;
    bytes public returndataFromB;
    uint256 public returndatasizeFromC;
    bytes public returndataFromC;

    constructor(address _B, address _C) {
        A = msg.sender;
        B = _B;
        C = _C;
    }

    function call() public {
        require(msg.sender == A, "Only A can call B");

        // 在这里调用BContract合约的getValue函数
        (bool success, bytes memory data) = B.call(
            abi.encodeWithSignature("getValue()")
        );
        require(success, "Call to B failed");
        resultFromB = abi.decode(data, (uint256));

        // 获取returndatasize和returndata
        (returndatasizeFromB, returndataFromB) = getResultData();

        // 调用成功后，接下来调用CContract合约的incrementCounter函数
        (success, data) = C.call(abi.encodeWithSignature("incrementCounter()"));
        require(success, "Call to C failed");
        counterFromC++;

        // 获取returndatasize和returndata
        (returndatasizeFromC, returndataFromC) = getResultData();
    }

    // 辅助函数，用于获取returndatasize和returndata
    function getResultData() internal pure returns (uint256, bytes memory) {
        uint256 size;
        assembly {
            size := returndatasize()
        }
        bytes memory data = new bytes(size);
        assembly {
            returndatacopy(data, 0, size)
        }
        return (size, data);
    }
}
