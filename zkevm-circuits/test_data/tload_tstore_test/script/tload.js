const {ethers} = require("hardhat");
const {deployTargetContract, getAbi, getChecksumAddress} = require("./utils")

const TransientAbi = getAbi("artifacts/contracts/Transient.sol/Transient.json");

const TransientContractAddr = getChecksumAddress("0x5fbdb2315678afecb367f032d93f642f64180aa3");

describe("TLOAD_TSTORE", function () {

    // 合约部署
    it("deploy_Transient", async function () {
        await deployTargetContract("Transient");
    });

    // 调用staticcall
    it("temporaryOperation", async function () {
        const [accountA] = await ethers.getSigners();
        console.log("accountA address:", accountA.address);
        console.log("contract address:", TransientContractAddr);
        const Transientcontract = await new ethers.Contract(TransientContractAddr, TransientAbi, accountA);

        const num = await Transientcontract.temporaryOperation();
        console.log("temporaryOperation finished, num:", num);
    });

});