const fs = require('fs');
const {ethers} = require("hardhat");

// 获取校验和的地址
function getChecksumAddress(address) {
    return ethers.getAddress(address);
}


// 从文件中获取abi
function getAbi(abiPath) {
    // 读取 ABI 文件
    const contractInfoJson = fs.readFileSync(abiPath, 'utf-8');

    // 将 JSON 字符串解析为 JavaScript 对象
    const contractInfo = JSON.parse(contractInfoJson);

    return contractInfo.abi;
}


// 合约部署
async function deployTargetContract(contractName) {
    console.log("start deploy contract:", contractName);

    const [accountA] = await ethers.getSigners();

    console.log("deploying Adder contract with the account:", accountA.address);

    const contractFactory = await ethers.getContractFactory(contractName);

    // 部署A合约
    const contract = await contractFactory.connect(accountA).deploy();

    // 等待A合约部署完成
    await contract.waitForDeployment();

    // 打印合约地址
    console.log("deployed %s to addr:", contractName, contract.target);
}

module.exports = {
    deployTargetContract,
    getAbi,
    getChecksumAddress
}