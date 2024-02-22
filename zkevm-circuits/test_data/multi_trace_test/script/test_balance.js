const { ethers } = require("hardhat");

describe("Ledger Balance Test", function () {
  it("Invoke Contract", async function () {
    // step 01 deploy
    const contract = await ethers.deployContract("LedgerBalance");

    // step 02 updateMyBalance
    txResponse1 = await contract.updateMyBalance(1000, {
      gasLimit: 100000,
    });
    console.log(txResponse1);

    // step 03 updateBalance
    toAddress = "0x66f6272fa66eb4e9a930ca12b1c415d19321666e";
    txResponse2 = await contract.updateBalance(200, toAddress, {
      gasLimit: 100000,
    });
    console.log(txResponse2);

    // step 04 transfer
    txResponse3 = await contract.transfer(toAddress, 500, {
      gasLimit: 100000,
    });
    console.log(txResponse3);

  });
});
