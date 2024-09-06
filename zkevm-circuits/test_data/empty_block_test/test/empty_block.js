const { ethers } = require("hardhat");

describe("Empty Block Test", function () {
  it("Contract", async function () {

    const blockCount = 5;
    for (let i = 0; i < blockCount; i++) {
      await network.provider.send("evm_mine");
    }

  });
});
