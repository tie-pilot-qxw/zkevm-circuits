// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract CContract {
    uint256 public counter;

    function incrementCounter() public {
        counter++;
    }
}
