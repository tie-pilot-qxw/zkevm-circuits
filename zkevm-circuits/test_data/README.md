# get json

本文档介绍如何运行zkevm所需要的数据。

# 使用 EVM 可执行文件生成

使用 EVM 可执行文件生成的主要用于简单测试的 Trace 数据，是通过输入字节码（bytecode）和调用数据（calldata）生成的 GethExecTrace。具体实现可以参考 `trace-parser/src/lib.rs` 中的 `trace_program` 和 `trace_program_with_log` 两个函数。在实际使用时，可以参考 `zkevm-circuits/tests/opcode_tests` 目录下的测试。

生成trace过程也可以在本地直接使用EVM可执行文件获取，例如：

```shell
$evm --code 6040 --json run
{
  "pc": 0,
  "op": 96,
  "gas": "0x2540be400",
  "gasCost": "0x3",
  "memSize": 0,
  "stack": [],
  "depth": 1,
  "refund": 0,
  "opName": "PUSH1"
}
{
  "pc": 2,
  "op": 0,
  "gas": "0x2540be3fd",
  "gasCost": "0x0",
  "memSize": 0,
  "stack": ["0x40"],
  "depth": 1,
  "refund": 0,
  "opName": "STOP"
}
{
  "output": "",
  "gasUsed": "0x3"
}
```

具体参数可以参考：[EVM tool](https://github.com/ethereum/go-ethereum/tree/master/cmd/evm)。

对于测试需要的其它数据，比如 block_info等，则需要手动设置对应的数据项，参考`trace_program_with_log`的实现。

然而，此方法存在一些局限性。当某些指令需要依赖链上的信息时，无法通过本地的 EVM 获取 Trace。例如，字节码包含了调用（CALL 指令）链上已部署的某个合约，在这种情况下，无法使用上述方法在本地生成对应的 Trace 数据。对于不支持的指令，可以通过下文的方法`在链上通过 API 获取`。

# 使用 evmutil 生成

针对error测试，可以使用 evmutil 工具生成。目录测试文件定位于 `zkevm/evmutil` 目录下，使用流程：

**1.  创建一个新的 go test 函数**
   
  命名为自己准备测试的函数名称，例如：
    

`func TestRootInvalidJump(t *testing.T)`

**2.  模拟写可能的合约运行逻辑**
例如下面是一个 invalid jump 错误类型：
    

```go
calleeOpcode := `  
PUSH1 0x1  
PUSH1 0x1  
JUMP  
PUSH1 0x0  
PUSH1 0x0  
JUMPDEST  
STOP  
`
```

**3.  写 account、tx、block 信息，具体含义如下所示：**
    

```go
accFuns := func(accs []*MockAccount) {  
    // mock一个账户，也即from  
    accs[0].  
       FromAddress("0x000000000000000000000000000000000000cafe").  
       Balance("0x8ac7230489e80000")  
    // to 调用合约  
    accs[1].  
       FromAddress("0xffffffffffffffffffffffffffffffffffffffff").  
       Code(OpcodeToBytes(calleeOpcode)).  // 自己写的bytecode在这里
       Balance("0x56bc75e2d63100000")  
  
}  
  
txFunc := func(txs []*MockTransaction, accs []*MockAccount) {  
	// 表示账户0调用账户1，且只有一笔交易
    txs[0].  
       FromAddress(accs[0].Address).  
       ToAddress(accs[1].Address).  
       SetGas(100000)  
}  

// 目前作用不大，可有可无
blockFunc := func(block *MockBlock, txs []*MockTransaction) {  
    block.Number = 100  
}
```

**4.  生成 trace 信息**
    

```go
// 这里我的test命名为root_invalid_jump，测试完成通过后，则在test_data目录下生成一个root_invalid_jump目录
err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 2, 1, "root_invalid_jump")  
if err != nil {  
    t.Fatal("expected error, err", err)  
}
```

**5.  写 zkevm 测试**
    

将上述生成的 `root_invalid_jump` 目录直接移动到 `zkevm-circuits/test_data/`目录下即可，按照 test 目录中的 test，例如 `call_trace_test.rs` 文件，复制代码进行简单的目录和函数名称修改即可。

注：  
以上主要是通用的测试模式，更多其他的测试生成 trace 流程可以参考现有的 test 案例。

# 在链上通过 API 获取

通过指定的 API 从链上获取包含 zkevm 所需数据的 JSON 文件。这些数据完全来源于链上的实际环境，是获取最准确数据的方式。

以 erc20 测试 `zkevm-circuits/test_data/erc20_test` 举例说明，参考`zkevm-circuits/test_data/erc20_test/test/token.js`将对应合约在链上部署执行，收集对应的区块号、交易哈希值等信息。

使用下述的命令获取json文件，其中，`localhost:8545` 应按实际情况替换为服务对应的地址和端口号。方法说明和参数等参考：[JSON-RPC API | ethereum.org](https://ethereum.org/en/developers/docs/apis/json-rpc/)。

**获取区块的信息**

```shell
curl localhost:8545 -X POST \
--data '{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": [
    "0x1",
    true
  ],
  "id": 1
}' | jq '.' > trace/t01_a_deploy_erc20/block_info.json

```

**获取合约字节码**

使用 prestate 参数，获取该交易关联的所有合约字节码。

```shell
curl localhost:8545 -X POST \
-H "Content-Type: application/json" \
--data '{
  "method":"debug_traceTransaction",
  "params":[
    "0xdb17c4ede91b98863972fc523eea6e85231f0470bd6821e1aa01c57f7b52b748",
    {
      "tracer": "prestateTracer",
      "tracerConfig": {"diffMode": false}
    }
  ],
  "id":1
}' | jq '.' > trace/t01_a_deploy_erc20/account.json
```

也可以使用`eth_getCode`获取指定地址的字节码。

```shell
curl localhost:8545 -X POST \
--data '{
  "jsonrpc": "2.0",
  "method": "eth_getCode",
  "params": [
    "0x5fbdb2315678afecb367f032d93f642f64180aa3",
    "0x1"
  ],
  "id": 1
}' | jq '.' > trace/t01_a_deploy_erc20/account.json

```

**获取trace**

```shell
curl localhost:8545 -X POST \
   -H "Content-Type: application/json" \
   --data '{
     "method": "debug_traceTransaction",
     "params": [
       "0xdb17c4ede91b98863972fc523eea6e85231f0470bd6821e1aa01c57f7b52b748"
     ],
     "id": 1,
     "jsonrpc": "2.0"
   }' | jq '.' > trace/t01_a_deploy_erc20/tx_debug_trace.json
```


**获取交易信息**

```shell
curl localhost:8545 -X POST --data '{
    "jsonrpc": "2.0",
    "method": "eth_getTransactionByHash",
    "params": ["0xdb17c4ede91b98863972fc523eea6e85231f0470bd6821e1aa01c57f7b52b748"],
    "id": 1
}' | jq '.' > trace/t01_a_deploy_erc20/tx_info.json

```

**获取收据信息**

```shell
curl localhost:8545 -X POST --data '{
    "jsonrpc": "2.0",
    "method": "eth_getTransactionReceipt",
    "params": ["0xdb17c4ede91b98863972fc523eea6e85231f0470bd6821e1aa01c57f7b52b748"],
    "id": 1
}' | jq '.' > trace/t01_a_deploy_erc20/tx_receipt.json
```