// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract A {
    uint256 public  data;
    event AReceiveMsgSender(address sender);
    event AReceiveMsgSenderWithData(address aMsgsender, address bMsgsender, address cMsgSender, uint256 dSetData, address dMsgSender);
    
    function delegateDelegateDelegate(address b, address c, address d, uint256 _data) public {
        (bool success, ) = b.delegatecall(
            abi.encodeWithSignature("delegateDelegate(address,address,uint256)",c,d, _data)
        );
        require(success, "Call to B failed");
        emit AReceiveMsgSender(msg.sender);
    }

    function callCallCall(address b, address c, address d, uint256 _data) public {
        (bool success, ) = b.call(
            abi.encodeWithSignature("callCall(address,address,uint256)",c,d, _data)
        );
        require(success, "Call to B failed");
        emit AReceiveMsgSender(msg.sender);
    }

    // 
    function staticStaticStatic(address b, address c, address d) public {
        (bool success,  bytes memory returnData) = b.call(
            abi.encodeWithSignature("staticStaticView(address,address)",c,d)
        );
        require(success, "Call to B failed");

        (address bMsgSender, address cMsgSender, uint256 dSetData, address dMsgSender) = abi.decode(returnData, (address, address, uint256, address));
        emit AReceiveMsgSenderWithData(msg.sender, bMsgSender, cMsgSender, dSetData, dMsgSender);
    }


    function getData() public view returns(uint256, address) {
        return (data, msg.sender);
    }

    function clear() public {
        data = 0;
    }
}