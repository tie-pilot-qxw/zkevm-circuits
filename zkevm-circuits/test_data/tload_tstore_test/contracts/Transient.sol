// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract Transient {
    function temporaryOperation() public returns (uint256) {
        uint256 value;
        assembly {
            // 存储临时值
            tstore(0x01, 0x1234)
            
            // 加载临时值
            value := tload(0x01)
        }
        return value;
    }
}
