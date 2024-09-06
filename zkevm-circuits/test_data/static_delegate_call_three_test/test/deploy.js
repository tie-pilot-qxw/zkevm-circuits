const {ethers} = require("hardhat");

const {deployTargetContract} = require("./utils")

    
describe("CONTRACT_DEPLOY", function () {
    // npx hardhat test --grep "contract_deploy" --network localhost
    it("contract_deploy", async function () {
        await deployTargetContract("A");
        await deployTargetContract("B");
        await deployTargetContract("C");
        await deployTargetContract("D");
    });

})