// 引入ethers，这在Hardhat环境中默认可用
const hre = require("hardhat");

async function main() {
    // 获取合约的编译工厂
    const SimpleStorage = await hre.ethers.getContractFactory("SimpleStorage");
    // 使用工厂部署合约
    const simpleStorage = await SimpleStorage.deploy();

    // 此处不再需要调用deployed()，因为deploy()已经确保合约部署完成
    console.log("SimpleStorage deployed to:", simpleStorage.address);
}

// 我们推荐这种模式来能够在任何地方使用async/await并正确处理错误
main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
