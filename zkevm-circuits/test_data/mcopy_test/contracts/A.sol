// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract A {
    function callSetNum(address ads, uint value) public {
        (bool success, ) = ads.call(
               abi.encodeWithSignature("SetNum(uint256)", value)
        );
       require(success, "call failed");
    }
}