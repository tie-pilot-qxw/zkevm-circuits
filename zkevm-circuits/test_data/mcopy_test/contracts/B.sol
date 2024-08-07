// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract B {
    uint    public num;
    address public addr;

    event sendAddr(address);
    function SetNum(uint _num) public {
        num = _num;
        addr = msg.sender;
        emit sendAddr(msg.sender);
    }

    function Clear() public {
        num = 0;
        addr = address(0);
    }

    function GetNum() public view returns(uint) {
        return num;
    }

    function GetAddress() public view returns(address) {
        return addr;
    }
}