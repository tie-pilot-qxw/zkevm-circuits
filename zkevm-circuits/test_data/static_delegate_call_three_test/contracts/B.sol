// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract B {
       
    uint256 public  data;
    event BReceiveMsgSender(address sender);
    event BReceiveMsgSenderWithData(address sender, address cMsgSender, uint256 dSetData, address dMsgSender);

    // B---delegatecall---> C ------delegatecall----->D
    function delegateDelegate(address c, address d, uint256 _data) public  {
        (bool success, ) =  c.delegatecall(
            abi.encodeWithSignature("delegatecallMe(address,uint256)",d, _data)
        );
        require(success, "Call to C failed");
        emit BReceiveMsgSender(msg.sender);
    }

    // B---delegatecall---> C ------call----->D
    function delegatCall(address c, address d, uint256 _data) public  {
        (bool success, ) =  c.delegatecall(
            abi.encodeWithSignature("callMe(address,uint256)",d, _data)
        );
        require(success, "Call to C failed");
        emit BReceiveMsgSender(msg.sender);
    }

    // B---delegatecall---> C ------staticcall----->D
    function delegatStatic(address c, address d) public  {
        (bool success,  bytes memory returnData) =  c.delegatecall(
            abi.encodeWithSignature("staticcallMeView(address)",d)
        );
        require(success, "Call to C failed");
       (address cMsgSender, uint256 dSetData, address dMsgSender) = abi.decode(returnData, (address, uint256, address));
        emit BReceiveMsgSenderWithData(msg.sender, cMsgSender, dSetData, dMsgSender);
    }


   // B---call---> C ------delegatecall----->D
    function callDelegate(address c, address d, uint256 _data) public  {
        (bool success, ) =  c.call(
            abi.encodeWithSignature("delegatecallMe(address,uint256)",d, _data)
        );
        require(success, "Call to C failed");
        emit BReceiveMsgSender(msg.sender);
    }

    // B---call---> C ------call----->D
    function callCall(address c, address d, uint256 _data) public  {
        (bool success, ) =  c.call(
            abi.encodeWithSignature("callMe(address,uint256)",d, _data)
        );
        require(success, "Call to C failed");
        emit BReceiveMsgSender(msg.sender);
    }

    // B---call---> C ------staticcall----->D
    function callStatic(address c, address d) public  {
        (bool success,  bytes memory returnData) =  c.call(
            abi.encodeWithSignature("staticcallMeView(address)",d)
        );
        require(success, "Call to C failed");
     (address cMsgSender, uint256 dSetData, address dMsgSender) = abi.decode(returnData, (address, uint256, address));
        emit BReceiveMsgSenderWithData(msg.sender, cMsgSender, dSetData, dMsgSender);
    }

    // staticcall只能调用pure或者view修饰的函数
    // B---staticcall---> C ------staticcall----->D
    function staticStatic(address c, address d) public  {
        (bool success,  bytes memory returnData) =  c.staticcall(
            abi.encodeWithSignature("staticcallMeView(address)",d)
        );
        require(success, "Call to C failed");
        (address cMsgSender, uint256 dSetData, address dMsgSender) = abi.decode(returnData, (address, uint256, address));
        emit BReceiveMsgSenderWithData(msg.sender, cMsgSender, dSetData, dMsgSender);
    }

      // B---staticcall---> C ------staticcall----->D
    function staticStaticView(address c, address d) public view returns(address, address, uint256, address) {
        (bool success,  bytes memory returnData) =  c.staticcall(
            abi.encodeWithSignature("staticcallMeView(address)",d)
        );
        require(success, "Call to C failed");
        (address cMsgSender, uint256 dSetData, address dMsgSender) = abi.decode(returnData, (address, uint256, address));
        return (msg.sender, cMsgSender, dSetData, dMsgSender);
    }


    function getData() public view returns(uint256, address) {
        return (data, msg.sender);
    }

    function clear() public {
        data = 0;
    }
}
