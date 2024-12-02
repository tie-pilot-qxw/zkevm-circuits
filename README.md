# 印客·Inker
**印客·Inker** 是一个实现零知识以太坊虚拟机电路的项目，用于验证以太坊智能合约的执行。

## 项目结构

```powershell
.
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── NOTICE
├── aggregate-zkevm # 用于聚合证明
├── csv2html # 用于csv转化为html的库
│   └── src
├── eth-types #以太坊相关的数据类型
│   └── src
├── evmutil # 用于生成测试数据
├── gadgets # 一些小工具
│   └── src
├── keccak256 # keccak256 相关工具
│   └── src
├── poseidon # poseidon 相关工具
├── prover # 使用zkevm封装的验证器
│   └── src
├── README.md
├── scripts # 用于benchmark测试/代码注释覆盖率/单元测试覆盖率统计脚本
├── trace-parser # 用于解析evm的trace的库
│   └── src
└── zkevm-circuits # zkevm电路代码
    ├── benches # bench测试
    ├── Cargo.toml
    ├── examples # 用于生成新gadget电路模板的工具类
    │   └── gen_code.rs
    ├── src # 电路源码
    │   ├── arithmetic_circuit # 各算术子电路
    │   ├── arithmetic_circuit.rs # 算术电路
    │   ├── bitwise_circuit.rs # 位运算电路
    │   ├── bytecode_circuit.rs # 字节码电路
    │   ├── constant.rs # 常量
    │   ├── copy_circuit.rs # copy电路
    │   ├── core_circuit.rs # core电路
    │   ├── execution # 各种指令执行电路
    │   ├── execution.rs # 执行中用到的一些公共代码
    │   ├── exp_circuit.rs # exp计算电路
    │   ├── fixed_circuit.rs # fixed电路
    │   ├── keccak_circuit # keccak256电路相关
    │   ├── keccak_circuit.rs # keccak256电路
    │   ├── lib.rs
    │   ├── poseidon_circuit.rs # poseidon电路
    │   ├── public_circuit_no_hash.rs 
    │   ├── public_circuit.rs # public电路
    │   ├── state_circuit # state电路相关
    │   ├── state_circuit.rs # state电路
    │   ├── super_circuit.rs # super电路
    │   ├── table.rs # 各电路互相查用到的table
    │   ├── util.rs # 一些工具函数
    │   ├── witness # witness相关代码
    │   └── witness.rs # witness相关代码
    ├── test_data # 测试数据
    └── tests # 测试相关
        ├── fuzz # mutate篡改测试
        └── opcode_tests # 用于单个opcode的测试
```

# 如何运行单元测试  

## 无需`evm`的单元测试  

主要用于验证`zkevm-circuits`中的各种电路工作逻辑的正确性。  
 
- 运行指定单测  

```shell
cargo test -p zkevm-circuits super_circuit::tests::test_super_circuit
```  

- 运行项目下所有测试  
  
```shell
cargo test -p zkevm-circuits
```

## 含有`evm`的单元测试  
  
运行含有EVM的测试，在使用测试命令的时候需要加上对应的feature "evm"。这类测试用于运行通过`evm`可执行文件加载测试中的solidity汇编指令产生trace，继而进行证明的测试。  

### 准备 evm可执行文件  
  
- 可以从[go-ethereum](https://github.com/ethereum/go-ethereum)下载源码，使用命令`go run build/ci.go install ./cmd/evm`安装。  

- 可以在[官网](https://geth.ethereum.org/downloads)下载相应版本的"Geth & Tools"工具，然后将`evm`可执行文件拷贝到`zkevm-circuits`目录下。  

### 运行项目下所有单元测试(含有EVM的测试)  

```shell
cargo test -p zkevm-circuits --features "default,evm"
```

## 查看生成的witness  

运行电路的单测时，会生成相应的witness；如果想查看witness的具体值,可以以html文件的形式进行输出。其关键代码片段如下:   
 
```rust
    let file_name = std::path::Path::new("./witness.html"); // 生成的html文件路径
    let mut buf = std::io::BufWriter::new(std::fs::File::create(file_name).unwrap());
    witness.write_html(&mut buf); // 将witness以html文件形式输出

```

# 运行`benchmark`测试

## 快速验证fast_test(small k，机器内存一般需要16G以上)  

### 生成验证参数  

预生成验证所需参数，将其写入到文件

```shell
cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- init_proof_params  --nocapture
```
### 运行电路  

- 使用生成的验证参数运行电路


```shell
USEFILE=true cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- super_circuit  --nocapture
```

- 运行电路不使用验证参数(每次运行重新生成)

```shell
cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- super_circuit  --nocapture
```

## 标准测试(k=19,机器内存一般需要256G以上)  

### 生成验证参数  

预生成验证所需参数，将其写入到文件

```shell
cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- init_proof_params  --nocapture
```
### 运行电路

- 使用生成的验证参数运行电路


```shell
USEFILE=true cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

- 运行电路不使用验证参数(每次运行重新生成)

```shell
cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

### 运行电路时可以指通过环境变量指定轮次

```shell
# round is 10
ROUND=10 cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

## 参数说明:

```--profile bench```：使用[profile.bench]

```--no-default-features```：关闭 "fast_test"特性

```--features "benches"```：打开这个feature会运行多轮

```--bench benchmark_list -- super_circuit```：运行`super_circuit`电路的 `benchmark`

## 将`benchmark`运行结果在`Grafana`中展示

在运行`benchmark`测试的时候，可以使用这里的[脚本](#bench-scripts)。如果仅运行测试，那么系统上仅需安装`sysstat`即可。若需要将测试结果做可视化，可以借助`grafana`。还需要确认以下[依赖项目都已安装](#bench_depends)。

#### Dependencies<a id="bench_depends"></a>

1. 依赖`sysstat`  

1. 依赖`python`：python3， pandas， sqlalchemy， pymysql

1. 依赖`mysql`：mysql(5.7+)， 提前准备好数据库，数据库的连接帐号，密码 将其写入到`scripts/report_system_data/env.json`文件 

1. 依赖 `grafana(10.3.3)`：
    
    - 在grafana的web页面上，首先增加`data source`；选择`mysql`模板，用`env.json`中的mysql信息填充该模板；需要注意的是`data source name`必须与文件 `grafana-bench-config.json`中的一致，默认值为bench_test
    
    - 在grafana的web页面上，使用`scripts/report_system_data/grafana-bench-config.json`来导入`Dashboard`面板

#### Bench scripts<a id="bench_scripts"></a>

1. 运行`benchmark`测试： 
 
```powershell
cd scripts && ./bench_test.sh $benchmark_list $sample_seconds
```

    
- `$benchmark_list`：指定运行哪个电路的bench，可以设置为`super_circuit`
    
- `$sample_seconds`：为cpu/mem的取样间隔，可以设置为`3`(意味着3s取样一次)  
         
    这一步会运行指定电路的bench测试，并按照设置的采样间隔，记录cpu/mem数据  
 
2. 将`benchmark`测试结果写入到`mysql`数据库：  
```powershell
cd scripts && ./record_bench_result_to_db.sh $test_id $log_file $cpu_file $mem_file [$delete_file]
```


    
- `$test_id`：如下文件log_file，cpu_file，mem_file的前缀
    
- `$log_file`：log文件
    
- `$cpu_file`：cpu采样文件
    
- `$mem_file` memory采样文件
    
- `$delete_file`：可选参数，若为`y`则删除 log_file，cpu_file，mem_file;  
  
    这个命令用于处理` log file， cpu file， mem file`文件，将处理结果写入到`mysql`数据库；若指定了删除文件参数为`y`，则处理后会删除这三个文件
      
3. 也提供了将步骤1和步骤2合为一步的命令：   

```powershell
cd scripts && ./bench_for_grafana.sh $benchmark_list $sample_seconds [$delete_file]
```

    
- `$benchmark_list`：指定运行哪个电路的bench，可以设置为`super_circuit`
    
- `$sample_seconds`：为cpu/mem的取样间隔，可以设置为`3`(意味着3s取样一次) 
    
- `$delete_file`：可选参数，若为`y`则删除 log_file，cpu_file，mem_file;
    
    这个命令一次完成了步骤1和步骤2的工作



# 代码审计  

本项目代码尚未经第三方审计，仅供学习研究。如需应用于生产环境，请谨慎使用。

# 参考资料

详细设计内容参考本项目Wiki。

# 许可  

本项目基于[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)协议开源, 请根据[LICENSE](./LICENSE)文件进行相关的操作。

# 致谢  
感谢[privacy-scaling-explorations项目](https://github.com/privacy-scaling-explorations/zkevm-circuits)的卓越工作，本项目从中受益匪浅。