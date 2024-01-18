const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying Adder contract with the account:", deployer.address);

  const B = await ethers.getContractFactory("BContract");
  const b = await B.deploy();
  console.log("B contract address:", b.target);
  
  const C = await ethers.getContractFactory("CContract");
  const c = await C.deploy();
  console.log("C contract address:", c.target);
  
  const A = await ethers.getContractFactory("MyContract");
  const a = await A.deploy(b.target,c.target);
  console.log("A contract address:", a.target);
  
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
