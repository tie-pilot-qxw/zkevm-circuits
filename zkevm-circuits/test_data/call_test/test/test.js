const { expect } = require("chai");

describe("Call", function () {
  it("call two kinds of functions", async function () {
  
    const B = await ethers.getContractFactory("BContract");
    const b = await B.deploy();
  
    const C = await ethers.getContractFactory("CContract");
    const c = await C.deploy();
  
    const A = await ethers.getContractFactory("MyContract");
    const a = await A.deploy(b.target,c.target);
  
    
    let  tx = await a.call();
    
    console.log(tx);
  });
});

