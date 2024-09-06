// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract C {
    uint256 public  data;
    event CReceiveMsgSender(address sender);
    event CReceiveMsgSenderWithData(address sender, uint256 dSetData, address dMsgSender);

    // C ------call----->D
    function callMe(address d, uint256 _data) public {
        (bool success, ) = d.call(
            abi.encodeWithSignature("setData(uint256)", _data)
        );
        require(success, "Call to D failed");
        emit CReceiveMsgSender(msg.sender);
    }

    // C ------delegatecall----->D
    function delegatecallMe(address d, uint256 _data) public {
        (bool success, ) = d.delegatecall(
            abi.encodeWithSignature("setData(uint256)", _data)
        );
        require(success, "Call to D failed");
        emit CReceiveMsgSender(msg.sender);
    }

    // C ------staticcall----->D
    // staticcall只能调用view和pure的修饰的函数
    function staticcallMe(address d) public returns(uint256){
        (bool success, bytes memory returnData) = d.staticcall(
            abi.encodeWithSignature("getData()")
        );
        require(success, "Call to D failed");
        (uint256 dSetData, address dMsgSender) = abi.decode(returnData, (uint256, address));
        emit CReceiveMsgSenderWithData(msg.sender, dSetData, dMsgSender);
        return dSetData;
    }

    // C ------staticcall----->D
    function staticcallMeView(address d) public view returns(address, uint256, address){
        (bool success, bytes memory returnData) = d.staticcall(
            abi.encodeWithSignature("getData()")
        );
        require(success, "Call to D failed");
        (uint256 dSetData, address dMsgSender) = abi.decode(returnData, (uint256, address));
        return (msg.sender, dSetData, dMsgSender);
    }


    function getData() public view returns(uint256, address) {
        return (data, msg.sender);
    }

    function clear() public {
        data = 0;
    }
}