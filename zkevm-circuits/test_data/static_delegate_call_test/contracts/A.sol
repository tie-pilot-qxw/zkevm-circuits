// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract A {
    uint    public num;
    address public addr;
    function callSetNum(address ads, uint value) public returns(uint) {
        (bool success, ) = ads.call(
               abi.encodeWithSignature("SetNum(uint256)", value)
        );
       require(success, "call failed");
    return value;
    }


    function delegatecallSetNum(address ads, uint value) public {
        (bool success, ) = ads.delegatecall(
               abi.encodeWithSignature("SetNum(uint256)", value)
        );
       require(success, "delegatecall failed");
    }


    function staticcallSetNum(address ads) public{
        (bool success, bytes memory data) = ads.staticcall(
            abi.encodeWithSignature("GetNum()")
        );
        require(success, "Static call failed");
        num = abi.decode(data, (uint));

    }

    function GetNum() public view returns(uint) {
        return num;
    }

    function GetAddress() public view returns(address) {
        return addr;
    }

    function Clear() public {
        num = 0;
        addr = address(0);
    }
}