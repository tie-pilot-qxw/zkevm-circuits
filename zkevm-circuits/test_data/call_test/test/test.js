const {ethers} = require("hardhat");
describe("Call", function () {
    it("call two kinds of functions", async function () {
        const [deployer] = await ethers.getSigners();

        console.log("Deploying Adder contract with the account:", deployer.address);

        const B = await ethers.getContractFactory("BContract");
        const b = await B.deploy();
        await b.waitForDeployment();
        console.log("b addr:", b.target);

        const C = await ethers.getContractFactory("CContract");
        const c = await C.deploy();
        await c.waitForDeployment();
        console.log("c addr:", c.target);

        const A = await ethers.getContractFactory("MyContract");
        const a = await A.deploy(b.target, c.target);
        await a.waitForDeployment();
        console.log("a addr:", a.target);


        let tx = await a.call();
        console.log(tx);

    });
});

