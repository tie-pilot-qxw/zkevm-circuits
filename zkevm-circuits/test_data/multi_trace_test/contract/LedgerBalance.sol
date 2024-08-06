// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.17;

contract LedgerBalance {
    mapping(address => uint) public balances;

    function updateMyBalance(uint newBalance) public {
        balances[msg.sender] = newBalance;
    }

    function updateBalance(uint _newBalance, address _to) public {
        balances[_to] = _newBalance;
    }

    function increaseBalance(address _to) public {
        balances[_to] += 1;
    }

    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(balances[_to] + _value >= balances[_to]);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
}
