// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract D {
    uint256 public  data;
    event DReceiveMsgSender(address sender);

    function setData(uint256 _data) public {
        data = _data;
        emit DReceiveMsgSender(msg.sender);
    }

    function getData() public view returns(uint256, address) {
        return (data, msg.sender);
    }

    function clear() public {
        data = 0;
    }
}