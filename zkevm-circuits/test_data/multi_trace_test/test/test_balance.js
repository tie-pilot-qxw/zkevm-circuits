const { ethers } = require("hardhat");

describe("Ledger Balance Test", function () {
  it("Invoke Contract", async function () {

    await network.provider.send("evm_setAutomine", [false]);
    await network.provider.send("evm_setIntervalMining", [0]);

    // step 01 deploy
    const contract = await ethers.deployContract("LedgerBalance");

    // step 02 updateMyBalance
    txResponse1 = await contract.updateMyBalance(1000, {
      gasLimit: 100000,
    });

    // step 03 updateBalance
    toAddress = "0x66f6272fa66eb4e9a930ca12b1c415d19321666e";
    txResponse2 = await contract.updateBalance(200, toAddress, {
      gasLimit: 100000,
    });

    // step 04 transfer
    txResponse3 = await contract.transfer(toAddress, 500, {
      gasLimit: 100000,
    });
    
    await network.provider.send("evm_mine");
    console.log(txResponse1);
    console.log(txResponse2);
    console.log(txResponse3);

  });
});
