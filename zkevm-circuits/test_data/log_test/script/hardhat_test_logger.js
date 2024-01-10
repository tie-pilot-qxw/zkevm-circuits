const { ethers } = require("hardhat");

describe("Log Opcode Test", function () {
  it("Invoke Contract test_log_all", async function () {
    const contract = await ethers.deployContract("Logger");
    // const contract = await ethers.getContractAt("Logger","0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0")
    let tx = await contract.test_log_all();
    console.log(tx);
  });
});
