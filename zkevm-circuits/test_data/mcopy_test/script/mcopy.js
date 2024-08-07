const {ethers} = require("hardhat");
const {deployTargetContract, getAbi, getChecksumAddress} = require("./utils")

const AAbi = getAbi("artifacts/contracts/A.sol/A.json");
const BAbi = getAbi("artifacts/contracts/B.sol/B.json");

const AContractAddr = getChecksumAddress("0x5fbdb2315678afecb367f032d93f642f64180aa3");
const BContractAddr = getChecksumAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512");

describe("MCOPY_TEST", function () {

    // 合约部署
    it("mcopy_deploy", async function () {
        await deployTargetContract("A");
        await deployTargetContract("B");
    });


    // 调用staticcall
    it("mcopy_call", async function () {
        const [accountA] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("contract address:", AContractAddr);
        const Acontract = await new ethers.Contract(AContractAddr, AAbi, accountA);
        const Bcontract = await new ethers.Contract(BContractAddr, BAbi, accountA);

        await Acontract.callSetNum(BContractAddr, 12);
        console.log("callSetNum finished");

        const num = await Bcontract.GetNum();
        const addr = await Bcontract.GetAddress();
        console.log("num:", num.toString(), ",addr:", addr);
    });

});
