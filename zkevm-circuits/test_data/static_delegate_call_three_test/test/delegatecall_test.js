const { expect } = require("chai");

const {AContractAddr, 
    BContractAddr, 
    CContractAddr, 
    DContractAddr,  
    get_contract_object,
    clear_call_value,
    get_normalcall_msg_sender,
    get_four_normalcall_msg_sender,
    get_staticcall_msg_sender,
    get_four_staticcall_msg_sender,} = require("./utils")


    describe("DELEGATECALL_TEST", function () {
        // 合约部署
        // A---delegatecall---> B---delegatecall---> C ------delegatecall----->D
        // npx hardhat test --grep "delegatecall01_three_delegatecall" --network localhost
        it("delegatecall01_three_delegatecall", async function(){
            const setValue = 10;

            // 获取合约对象
            const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();

            // 初始化值
            console.log("[initial value]")
            await clear_call_value([AContract, BContract, CContract, DContract]);
            console.log();

            // 调用合约方法
            const tx = await AContract.delegateDelegateDelegate(BContract, CContractAddr, DContractAddr, setValue);
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
            const [afterDData] = await DContract.getData();

            console.log(`after call, A contract, data: ${afterAData.toString()}`);
            console.log(`after call, B contract, data: ${afterBData.toString()}`);
            console.log(`after call, C contract, data: ${afterCData.toString()}`);
            console.log(`after call, D contract, data: ${afterDData.toString()}`);
            console.log();

            // 断言
            // 因为整条调用链路都是使用Delegatecall完成的，所以操作的都是同一个上下为，即A合约的上下文
            expect(afterAData).to.equal(setValue);
            expect(AMsgSender).to.equal(accountA.address);

            expect(afterBData).to.equal(0);
            expect(BMsgSender).to.equal(accountA.address);

            expect(afterCData).to.equal(0);
            expect(CMsgSender).to.equal(accountA.address);

            expect(afterDData).to.equal(0);
            expect(DMsgSender).to.equal(accountA.address);

        });

        // B---delegatecall---> C ------delegatecall----->D
        // npx hardhat test --grep "delegatecall02_two_delegatecall" --network localhost
        it("delegatecall02_two_delegatecall", async function(){
            const setValue = 10;
    
            // 获取合约对象
            const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();
    
            // 初始化值
            console.log("[initial value]")
            await clear_call_value([AContract, BContract, CContract, DContract]);
            console.log();
    
            // 调用合约方法
            const tx = await BContract.delegateDelegate(CContractAddr, DContractAddr, setValue);
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
            const [afterDData] = await DContract.getData();
    
            console.log(`after call, B contract, data: ${afterBData.toString()}`);
            console.log(`after call, C contract, data: ${afterCData.toString()}`);
            console.log(`after call, D contract, data: ${afterDData.toString()}`);
            console.log();
    
            // 断言
            expect(afterBData).to.equal(setValue);
            expect(BMsgSender).to.equal(accountA.address);
    
            expect(afterCData).to.equal(0);
            expect(CMsgSender).to.equal(accountA.address);
    
            expect(afterDData).to.equal(0);
            expect(DMsgSender).to.equal(accountA.address);
    
        });
    
        // B---delegatecall---> C ------call----->D
        // npx hardhat test --grep "t03_delegatecall_call" --network localhost
        it("delegatecall03_delegatecall_call", async function(){
            const setValue = 10;
    
            // 获取合约对象
            const { accountA, AContract, BContract, CContract, DContract} = await get_contract_object();
    
            // 初始化值
            console.log("[initial value]")
            await clear_call_value([AContract, BContract, CContract, DContract]);
            console.log();
    
            // 调用合约方法
            const tx = await BContract.delegatCall(CContractAddr, DContractAddr, setValue);
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
            const [afterDData] = await DContract.getData();
    
            console.log(`after call, B contract, data: ${afterBData.toString()}`);
            console.log(`after call, C contract, data: ${afterCData.toString()}`);
            console.log(`after call, D contract, data: ${afterDData.toString()}`);
            console.log();
    
            // 断言
            // B---DelegateCall--->C, 所以C和B所处的是同一个上下文环境，可以看作是同一个合约
            // 所以D的msg.Sender为B的地址
            expect(afterBData).to.equal(0);
            expect(BMsgSender).to.equal(accountA.address);
            expect(afterCData).to.equal(0);
            expect(CMsgSender).to.equal(accountA.address);
    
            expect(afterDData).to.equal(setValue);
            expect(DMsgSender).to.equal(BContractAddr);
    
        });
    
    
            // B---delegatecall---> C ------staticcall----->D
        // npx hardhat test --grep "delegatecall04_delegatecall_staticcall" --network localhost
        it("delegatecall04_delegatecall_staticcall", async function(){
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
            const tx = await BContract.delegatStatic(CContractAddr, DContractAddr);
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
            // B---DelegateCall--->C, 所以C和B所处的是同一个上下文环境，可以看作是同一个合约
            // 所以D的msg.Sender为B的地址
            expect(afterBData).to.equal(0);
            expect(BMsgSender).to.equal(accountA.address);
            expect(afterCData).to.equal(0);
            expect(CMsgSender).to.equal(accountA.address);
    
            expect(DSetData).to.equal(setValue);
            expect(afterDData).to.equal(setValue);
            expect(DMsgSender).to.equal(BContractAddr);
        });
    
    })
    