

const { expect } = require("chai");

const {
    AContractAddr, 
    BContractAddr, 
    CContractAddr, 
    DContractAddr,  
    get_contract_object,
    clear_call_value,
    get_normalcall_msg_sender,
    get_four_normalcall_msg_sender,
    get_staticcall_msg_sender
} = require("./utils")

describe("CALL_TEST", function () {
    // 合约部署

    // A---call---> B---call---> C ------call----->D
    // npx hardhat test --grep "call01_three_call" --network localhost
    it("call01_three_call", async function(){
        const setValue = 10;

        // 获取合约对象
        const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

        // 初始化值
        console.log("[initial value]")
        await clear_call_value([AContract, BContract, CContract, DContract]);
        console.log();

        // 调用合约方法
        const tx = await AContract.callCallCall(BContract, CContractAddr, DContractAddr, setValue);
        const receipt = await tx.wait();
        let blockNum = receipt.blockNumber;
        console.log(`blockNum: ${blockNum}`);
        let txHash = receipt.hash;
        console.log(`txHash: ${txHash}`);
        let {AMsgSender, BMsgSender, CMsgSender, DMsgSender} = await get_four_normalcall_msg_sender(receipt.logs);
        console.log(`call event value, AMsgSender: ${AMsgSender}, BMsgSender: ${BMsgSender},  CMsgSender: ${CMsgSender}, DMsgSender: ${DMsgSender}` );
        console.log();


        console.log("[after call]")
        const [afterAData] = await AContract.getData();
        const [afterBData] = await BContract.getData();
        const [afterCData] = await CContract.getData();
        const [aferDData] = await DContract.getData();

        console.log(`after call, A contract, data: ${afterAData.toString()}`);
        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, B contract, data: ${afterCData.toString()}`);
        console.log(`after call, C contract, data: ${aferDData.toString()}`);
        console.log();

        // 断言
        // 因为整条调用链路都是使用Delegatecall完成的，所以操作的都是同一个上下为，即A合约的上下文
        expect(afterAData).to.equal(0);
        expect(AMsgSender).to.equal(accountA.address);

        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(AContractAddr);

        expect(afterCData).to.equal(0);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(aferDData).to.equal(setValue);
        expect(DMsgSender).to.equal(CContractAddr);

    });

     // B---call---> C ------call----->D
    // npx hardhat test --grep "t06_call_call" --network localhost
    it("call02_two_call", async function(){
        const setValue = 10;

        // 获取合约对象
        const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

        // 初始化值
        console.log("[initial value]")
        await clear_call_value([AContract, BContract, CContract, DContract]);
        console.log();

        // 调用合约方法
        const tx = await BContract.callCall(CContractAddr, DContractAddr, setValue);
        const receipt = await tx.wait();
        let blockNum = receipt.blockNumber;
        console.log(`blockNum: ${blockNum}`);
        let txHash = receipt.hash;
        console.log(`txHash: ${txHash}`);
        let {BMsgSender, CMsgSender, DMsgSender} = await get_normalcall_msg_sender(receipt.logs);
        console.log(`call event value, BMsgSender: ${BMsgSender},  CMsgSender: ${CMsgSender}, DMsgSender: ${DMsgSender}` );
        console.log();


        console.log("[after call]")
        const [afterBData] = await BContract.getData();
        const [afterCData] = await CContract.getData();
        const [aferDData] = await DContract.getData();

        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, B contract, data: ${afterCData.toString()}`);
        console.log(`after call, C contract, data: ${aferDData.toString()}`);
        console.log();

        // 断言
        // 互相上下文都是独立的
        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(accountA.address);
        expect(afterCData).to.equal(0);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(aferDData).to.equal(setValue);
        expect(DMsgSender).to.equal(CContractAddr);

    });



    //B---call---> C ------delegatecall----->D
    // npx hardhat test --grep "t05_call_delegatecall" --network localhost
    it("call03_call_delegatecall", async function(){
        const setValue = 10;

        // 获取合约对象
        const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

        // 初始化值
        console.log("[initial value]")
        await clear_call_value([AContract, BContract, CContract, DContract]);
        console.log();

        // 调用合约方法
        const tx = await BContract.callDelegate(CContractAddr, DContractAddr, setValue);
        const receipt = await tx.wait();
        let blockNum = receipt.blockNumber;
        console.log(`blockNum: ${blockNum}`);
        let txHash = receipt.hash;
        console.log(`txHash: ${txHash}`);
        let {BMsgSender, CMsgSender, DMsgSender} = await get_normalcall_msg_sender(receipt.logs);
        console.log(`call event value, BMsgSender: ${BMsgSender},  CMsgSender: ${CMsgSender}, DMsgSender: ${DMsgSender}` );
        console.log();


        console.log("[after call]")
        const [afterBData] = await BContract.getData();
        const [afterCData] = await CContract.getData();
        const [aferDData] = await DContract.getData();

        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, B contract, data: ${afterCData.toString()}`);
        console.log(`after call, C contract, data: ${aferDData.toString()}`);
        console.log();

        // 断言
        // 因为是C---DelegateCall---D，所以D和C所处的是同一个上下文环境，看到的msgSender都是B, 所修改的值也为C的值
        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(accountA.address);

        expect(afterCData).to.equal(setValue);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(aferDData).to.equal(0);
        expect(DMsgSender).to.equal(BContractAddr);

    });

   


    // B---call---> C ------staticcall----->D
    // npx hardhat test --grep "t07_call_staticacall" --network localhost
    it("call04_call_staticacall", async function(){
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
        const tx = await BContract.callStatic(CContractAddr, DContractAddr);
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
        const [aferDData] = await DContract.getData();

        console.log(`after call, B contract, data: ${afterBData.toString()}`);
        console.log(`after call, B contract, data: ${afterCData.toString()}`);
        console.log(`after call, C contract, data: ${aferDData.toString()}`);
        console.log();

        // 断言
        // 互相之间的上下文是独立的
        expect(afterBData).to.equal(0);
        expect(BMsgSender).to.equal(accountA.address);

        expect(afterCData).to.equal(0);
        expect(CMsgSender).to.equal(BContractAddr);

        expect(DSetData).to.equal(setValue);
        expect(aferDData).to.equal(setValue);
        expect(DMsgSender).to.equal(CContractAddr);
    });

})
