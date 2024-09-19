// note:
// 1. 部署一次合约；
// 2. 调用两次set操作，第一次set 520， 此时gas cost是22100，符合预期结果；
// 3. 第二次set 331，此时gas cost是5000，根据gas计算规则，冷启动并且original不为空，则5000
const { expect } = require("chai");
const fs = require('fs');
const { ethers } = require("hardhat");

// 合约地址
const contractAddr = getChecksumAddress("0x5fbdb2315678afecb367f032d93f642f64180aa3");

function getChecksumAddress(address) {
  return ethers.getAddress(address);
}


const abi = getAbi();

console.log("经过校验和后的合约地址：", contractAddr)

function getAbi() {
    const contractInfoJsonPath = "artifacts/contracts/SimpleStorage.sol/SimpleStorage.json";

    const contractInfoJson = fs.readFileSync(contractInfoJsonPath, 'utf-8');
      
    const contractInfo = JSON.parse(contractInfoJson);

    return contractInfo.abi;
}


describe("SimpleStorage Test", function () {
  it("Invoke Contract", async function () {
    const [accountA] = await ethers.getSigners();
    const contract = new ethers.Contract(contractAddr, abi, accountA);
    console.log("accountA address:", accountA.address);console.log("accountA address:", accountA.address);

    txResponse1 = await contract.set(331);
    console.log(txResponse1);
  });
});
