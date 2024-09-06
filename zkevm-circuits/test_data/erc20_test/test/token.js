const { expect } = require("chai");
const fs = require('fs');
const { ethers } = require("hardhat");

// 合约的只读方法，也称为“view”或“pure”，不会对区块链状态进行修改，因此在调用这些方法时不会生成交易

// 以太坊节点url
const ethLocalUrl = "http://localhost:8545"

// 合约地址
// 地址全小写会校验和错误
// 在以太坊中，为了提高地址的可读性和减少用户输入错误，使用了地址校验和（Checksum Address）机制。这种机制通过在地址的特定位置插入大写字母，使地址包含一定的大小写信息。
const contractAddr = getChecksumAddress("0x5fbdb2315678afecb367f032d93f642f64180aa3");

// abis
const abi = getAbi();

console.log("经过校验和后的合约地址：", contractAddr)


// 从文件中获取abi
function getAbi() {
    const contractInfoJsonPath = "artifacts/contracts/Token.sol/Token.json";
    // 读取 ABI 文件
    const contractInfoJson = fs.readFileSync(contractInfoJsonPath, 'utf-8');
      
    // 将 JSON 字符串解析为 JavaScript 对象
    const contractInfo = JSON.parse(contractInfoJson);

    return contractInfo.abi;
}

// 获取校验和的地址
function getChecksumAddress(address) {
    return ethers.getAddress(address);
  }
  

// Token 合约相关部署
describe("Token contract", function() {

    // 合约部署
    it("t01_deploy", async function() {
        const [accountA] = await ethers.getSigners();

        // 获取token 合约对象
        const Token = await ethers.getContractFactory("Token");

        // 部署token合约
        const contractObj = await Token.connect(accountA).deploy("Gold", "GLD", 180000);

        // 等待合约部署完成
        await contractObj.waitForDeployment();
        
        // 打印合约地址
        console.log("deployed to addr:", contractObj.target);

        // 查看余额
        const totalSupply = await contractObj.totalSupply();
        const ownerBalance = await contractObj.balanceOf(accountA.address);
        console.log("accountA balance:", ownerBalance.toString());

        // 验证余额
        expect(totalSupply).to.equal(ownerBalance);
    });


    // 合约调用 accountA transfer accountB  200
    it("t02_a_transfer_b_200", async function() {

        const [accountA, accountB, accountC] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("accountB address:", accountB.address);
        const contractObj = await new ethers.Contract(contractAddr, abi, accountA);

        //调用合约方法
        await contractObj.transfer(accountB.address, 200);
        console.log("transfer finished");

        //调用合约方法
        const totalSupply = await contractObj.totalSupply();
        const accountABalance = await contractObj.balanceOf(accountA.address);
        const accountBBalance = await contractObj.balanceOf(accountB.address);
        const accountCAllowanceBalance = await contractObj.allowance(accountA.address, accountC.address);
        console.log("totalSupply", totalSupply.toString())
        console.log("accountA balance", accountABalance.toString())
        console.log("accountB balance", accountBBalance.toString())
        console.log("accountC allowance balance", accountCAllowanceBalance.toString())


        // 验证余额
        expect(totalSupply).to.equal(accountABalance + BigInt(200));
        expect(accountBBalance).to.equal(BigInt(200));
        expect(accountCAllowanceBalance).to.equal(BigInt(0));
    });


    // 金额授权 accountA 授权给 accountC  200
    it("t03_a_approve_c_200", async function() {

        const [accountA, accountB, accountC] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("accountC address:", accountC.address);
        const contractObj = await new ethers.Contract(contractAddr, abi, accountA);

        //调用合约方法
        await contractObj.approve(accountC.address, 200);
        console.log("approve finished");

         //调用合约方法
         const totalSupply = await contractObj.totalSupply();
         const accountABalance = await contractObj.balanceOf(accountA.address);
         const accountBBalance = await contractObj.balanceOf(accountB.address);
         const accountCAllowanceBalance = await contractObj.allowance(accountA.address, accountC.address);
         console.log("totalSupply", totalSupply.toString())
         console.log("accountA balance", accountABalance.toString())
         console.log("accountB balance", accountBBalance.toString())
         console.log("accountC allowance balance", accountCAllowanceBalance.toString())
 
 
         // 验证余额
         expect(totalSupply).to.equal(accountABalance + BigInt(200));
         expect(accountBBalance).to.equal(BigInt(200));
         expect(accountCAllowanceBalance).to.equal(BigInt(200));
    });


    // 使用被许可的的金额转账
    // 使用accountC账户调用 transferFrom， 让accountA 转给 accountB 200
    it("t04_c_transfer_from_a_b_200", async function() {

        const [accountA, accountB, accountC] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("accountB address:", accountB.address);
        console.log("accountC address:", accountC.address);
        const contractObj = await new ethers.Contract(contractAddr, abi, accountC);

        //调用合约方法
        await contractObj.transferFrom(accountA.address, accountB.address, 200);
        console.log("transfer finished");


         //调用合约方法
         const totalSupply = await contractObj.totalSupply();
         const accountABalance = await contractObj.balanceOf(accountA.address);
         const accountBBalance = await contractObj.balanceOf(accountB.address);
         const accountCAllowanceBalance = await contractObj.allowance(accountA.address, accountC.address);
         console.log("totalSupply", totalSupply.toString())
         console.log("accountA balance", accountABalance.toString())
         console.log("accountB balance", accountBBalance.toString())
         console.log("accountC allowance balance", accountCAllowanceBalance.toString())
 
 
         // 验证余额
         expect(totalSupply).to.equal(accountABalance + BigInt(400));
         expect(accountBBalance).to.equal(BigInt(400));
         expect(accountCAllowanceBalance).to.equal(BigInt(0));
    });

    // 合约调用balance_of
    it("token_balance", async function() {

        const [accountA, accountB, accountC] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("accountB address:", accountB.address);
        console.log("accountC address:", accountC.address);
        const contractObj = await new ethers.Contract(contractAddr, abi, accountA);

        //调用合约方法
        let accountABalance = await contractObj.balanceOf(accountA.address);
        let accountBBalance = await contractObj.balanceOf(accountB.address);
        let accountCAllowanceBalance = await contractObj.allowance(accountA.address, accountC.address);
        console.log("accountA balance", accountABalance.toString())
        console.log("accountB balance", accountBBalance.toString())
        console.log("accountC allowance balance", accountCAllowanceBalance.toString())

    });
    
});

