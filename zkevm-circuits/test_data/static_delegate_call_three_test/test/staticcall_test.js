
const {ethers} = require("hardhat");
const { expect } = require("chai");

const {
    AContractAddr, 
    BContractAddr, 
    CContractAddr, 
    DContractAddr,  
    get_contract_object,
    clear_call_value,
    get_staticcall_msg_sender,
    get_four_staticcall_msg_sender,
} = require("./utils")

describe("STATICCALL_TEST", function () {
    // 合约部署
        // A---staticcall--->B---staticcall---> C ------staticcall----->D
    // npx hardhat test --grep "staticcall01_three_staticacall" --network localhost
    it("staticcall01_three_staticacall", async function(){
        const setValue = 10;

        // 获取合约对象
        const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

        // 初始化值
        console.log("[initial value]")
        await clear_call_value([AContract, BContract, CContract, DContract]);
        console.log();

        // 先为Dset一个value
        const DTx = await DContract.setData(setValue);
        const DReceipt = await DTx.wait();
        let DBlockNum = DReceipt.blockNumber;
        console.log(`DBlockNum: ${DBlockNum}`);
        let DTxHash = DReceipt.hash;
        console.log(`DTxHash: ${DTxHash}`);
        console.log();

        // 调用合约方法
        const tx = await AContract.staticStaticStatic(BContractAddr, CContractAddr, DContractAddr);
        const receipt = await tx.wait();
        let blockNum = receipt.blockNumber;
        console.log(`blockNum: ${blockNum}`);
        let txHash = receipt.hash;
        console.log(`txHash: ${txHash}`);
        let {AMsgSender, BMsgSender, CMsgSender, DSetData, DMsgSender} = await get_four_staticcall_msg_sender(receipt.logs);
        console.log(`call event value, AMsgSender: ${AMsgSender}, BMsgSender: ${BMsgSender},  CMsgSender: ${CMsgSender}, DSetData:${DSetData}, DMsgSender: ${DMsgSender}` );
        console.log();


        console.log("[after call]")
        const [afterAData] = await AContract.getData();
        const [afterBData] = await BContract.getData();
        const [afterCData] = await CContract.getData();
        const [afterDData] = await DContract.getData();

        console.log(`after call, A contract, data: ${afterAData.toString()}`);
        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, C contract, data: ${afterCData.toString()}`);
        console.log(`after call, D contract, data: ${afterDData.toString()}`);
        console.log();

        // 断言
        // 互相之间的上下文是独立的
        expect(afterAData).to.equal(0);
        expect(AMsgSender).to.equal(accountA.address);

        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(AContractAddr);

        expect(afterCData).to.equal(0);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(DSetData).to.equal(setValue);
        expect(afterDData).to.equal(setValue);
        expect(DMsgSender).to.equal(CContractAddr);
    });

    // B---staticcall---> C ------staticcall----->D
    // npx hardhat test --grep "t08_staticcall_staticacall" --network localhost
    it("staticcall02_two_staticacall", async function(){
        const setValue = 10;

        // 获取合约对象
        const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

        // 初始化值
        console.log("[initial value]")
        await clear_call_value([AContract, BContract, CContract, DContract]);
        console.log();

        // 先为Dset一个value
        const DTx = await DContract.setData(setValue);
        const DReceipt = await DTx.wait();
        let DBlockNum = DReceipt.blockNumber;
        console.log(`DBlockNum: ${DBlockNum}`);
        let DTxHash = DReceipt.hash;
        console.log(`DTxHash: ${DTxHash}`);
        console.log();

        // 调用合约方法
        const tx = await BContract.staticStatic(CContractAddr, DContractAddr);
        const receipt = await tx.wait();
        let blockNum = receipt.blockNumber;
        console.log(`blockNum: ${blockNum}`);
        let txHash = receipt.hash;
        console.log(`txHash: ${txHash}`);
        let {BMsgSender, CMsgSender, DSetData, DMsgSender} = await get_staticcall_msg_sender(receipt.logs);
        console.log(`call event value, BMsgSender: ${BMsgSender},  CMsgSender: ${CMsgSender}, DSetData:${DSetData}, DMsgSender: ${DMsgSender}` );
        console.log();


        console.log("[after call]")
        const [afterBData] = await BContract.getData();
        const [afterCData] = await CContract.getData();
        const [afterDData] = await DContract.getData();

        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, C contract, data: ${afterCData.toString()}`);
        console.log(`after call, D contract, data: ${afterDData.toString()}`);
        console.log();

        // 断言
        // 互相之间的上下文是独立的
        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(accountA.address);

        expect(afterCData).to.equal(0);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(DSetData).to.equal(setValue);
        expect(afterDData).to.equal(setValue);
        expect(DMsgSender).to.equal(CContractAddr);
    });

})