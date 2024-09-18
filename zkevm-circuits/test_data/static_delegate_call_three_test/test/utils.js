const fs = require('fs');
const { ethers } = require("hardhat");
const { Interface } = ethers;
const { expect } = require("chai");

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

const AAbi = getAbi("artifacts/contracts/A.sol/A.json");
const BAbi = getAbi("artifacts/contracts/B.sol/B.json");
const CAbi = getAbi("artifacts/contracts/C.sol/C.json");
const DAbi = getAbi("artifacts/contracts/D.sol/D.json");

// replace with the addresses just deployed
const AContractAddr = getChecksumAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3");
const BContractAddr = getChecksumAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512");
const CContractAddr = getChecksumAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
const DContractAddr = getChecksumAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");

async function get_contract_object() {
    const [accountA] = await ethers.getSigners();
    console.log("Sender address:", accountA.address);
    console.log("A contract address:", AContractAddr);
    console.log("B contract address:", BContractAddr);
    console.log("C contract address:", CContractAddr);
    console.log("D contract address:", DContractAddr);
    console.log();

    // 构建合约对象
    const AContract = await new ethers.Contract(AContractAddr, AAbi, accountA);
    const BContract = await new ethers.Contract(BContractAddr, BAbi, accountA);
    const CContract = await new ethers.Contract(CContractAddr, CAbi, accountA);
    const DContract = await new ethers.Contract(DContractAddr, DAbi, accountA);
    
    return { accountA, AContract, BContract, CContract, DContract };
}

async function clear_call_value(contracts) {
    // Clear all contracts in a loop
    for (const contract of contracts) {
        console.log(`start init, contract:${contract.target}`);
        const txClear = await contract.clear();
        await txClear.wait();

        // 校验值
        const [data] = await contract.getData();
        console.log(`after init, contract:${contract.target}, data: ${data.toString()}`);
        expect(data).to.equal(0);
    }
}


// 适用于： 
// B---delegatecall---> C ------delegatecall----->D
// B---delegatecall---> C ------call----->D
// B---call---> C ------delegatecall----->D
// B---call---> C ------call----->D
async function get_normalcall_msg_sender(logs) {
    const BIface = new Interface(BAbi);
    const CIface = new Interface(CAbi);
    const DIface = new Interface(DAbi);
    let BMsgSender, CMsgSender, DMsgSender;

    // console.log(logs)
    logs.forEach(log => {
        // event log解析
        const BParsedLog = BIface.parseLog(log);
        if (BParsedLog && BParsedLog.name === "BReceiveMsgSender"){
            BMsgSender = BParsedLog.args[0]; 
        }
        const CParsedLog = CIface.parseLog(log);
        if (CParsedLog && CParsedLog.name === "CReceiveMsgSender") {
            CMsgSender = CParsedLog.args[0];
        }
        const DParsedLog = DIface.parseLog(log);
        if (DParsedLog && DParsedLog.name === "DReceiveMsgSender") {
            DMsgSender = DParsedLog.args[0];
        }
    });

    return {BMsgSender, CMsgSender, DMsgSender}
}

// 适用于： 
// B---delegatecall---> C ------delegatecall----->D
// B---delegatecall---> C ------call----->D
// B---call---> C ------delegatecall----->D
// B---call---> C ------call----->D
async function get_four_normalcall_msg_sender(logs) {
    const AIface = new Interface(AAbi);
    const BIface = new Interface(BAbi);
    const CIface = new Interface(CAbi);
    const DIface = new Interface(DAbi);
    let AMsgSender, BMsgSender, CMsgSender, DMsgSender;

    // console.log(logs)
    logs.forEach(log => {
        // event log解析
        const AParsedLog = AIface.parseLog(log);
        if (AParsedLog && AParsedLog.name === "AReceiveMsgSender"){
            AMsgSender = AParsedLog.args[0]; 
        }
        const BParsedLog = BIface.parseLog(log);
        if (BParsedLog && BParsedLog.name === "BReceiveMsgSender"){
            BMsgSender = BParsedLog.args[0]; 
        }
        const CParsedLog = CIface.parseLog(log);
        if (CParsedLog && CParsedLog.name === "CReceiveMsgSender") {
            CMsgSender = CParsedLog.args[0];
        }
        const DParsedLog = DIface.parseLog(log);
        if (DParsedLog && DParsedLog.name === "DReceiveMsgSender") {
            DMsgSender = DParsedLog.args[0];
        }
    });

    return {AMsgSender, BMsgSender, CMsgSender, DMsgSender}
}

// 适用于: 
// B---delegatecall---> C ------staticcall----->D
// B---call---> C ------staticcall----->D
// B---staticcall---> C ------staticcall----->D
async function get_staticcall_msg_sender(logs) {
    const BIface = new Interface(BAbi);
    let BMsgSender, CMsgSender, DSetData, DMsgSender;
    logs.forEach(log => {
        // event log解析
        const parsedLog = BIface.parseLog(log);
        if (parsedLog.name === "BReceiveMsgSenderWithData") {
            [BMsgSender, CMsgSender, DSetData, DMsgSender] = parsedLog.args;
        }
    });
    return {BMsgSender, CMsgSender, DSetData, DMsgSender}
}


async function get_four_staticcall_msg_sender(logs) {
    const AIface = new Interface(AAbi);
    let AMsgSender, BMsgSender, CMsgSender, DSetData, DMsgSender;
    logs.forEach(log => {
        // event log解析
        const AParsedLog = AIface.parseLog(log);
        if (AParsedLog && AParsedLog.name === "AReceiveMsgSenderWithData"){
            [AMsgSender, BMsgSender, CMsgSender, DSetData, DMsgSender] = AParsedLog.args;
        }
    });
    return {AMsgSender, BMsgSender, CMsgSender, DSetData, DMsgSender}
}


module.exports = {
    deployTargetContract,
    getAbi,
    getChecksumAddress,
    AContractAddr, 
    BContractAddr, 
    CContractAddr, 
    DContractAddr,  
    get_contract_object,
    clear_call_value,
    get_normalcall_msg_sender,
    get_four_normalcall_msg_sender,
    get_staticcall_msg_sender,
    get_four_staticcall_msg_sender,
}


