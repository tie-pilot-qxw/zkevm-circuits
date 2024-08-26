// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evm_util

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"os"
	"strings"
	"time"
)

func OpcodeToBytes(opcodes string) []byte {
	// 定义一个包含操作码的字符串
	// 例如 PUSH1 0x60 PUSH1 0x40 MSTORE

	// 将操作码字符串分割成单个操作码
	ops := strings.Fields(opcodes)

	var bytecode []byte

	for i := 0; i < len(ops); i++ {
		op := ops[i]
		opcode := vm.StringToOp(op)
		bytecode = append(bytecode, byte(opcode))

		// 如果是 PUSH 操作码，处理后续的立即数
		if strings.HasPrefix(op, "PUSH") {
			i++ // 跳过操作码后的立即数
			immediate := ops[i]
			value := common.FromHex(immediate)
			bytecode = append(bytecode, value...)
		}
	}
	return bytecode
}

func timeStamp() *hexutil.Big {
	unixTimestamp := time.Now().Unix()
	bigIntTimestamp := big.NewInt(unixTimestamp)
	return (*hexutil.Big)(bigIntTimestamp)
}

func hexToHexBig(s string) *hexutil.Big {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	b := new(big.Int)
	b.SetString(s, 16)
	return (*hexutil.Big)(b)
}

func bigIntToHexBig(a *big.Int) *hexutil.Big {
	return (*hexutil.Big)(a)
}

func uint64ToHexUint64(a uint64) hexutil.Uint64 {
	return (hexutil.Uint64)(a)
}

func hexBigToBigInt(value *hexutil.Big) *big.Int {
	if value != nil {
		return value.ToInt()
	}
	return big.NewInt(0)
}

func createJson(path string, data interface{}) error {
	// 处理MockTransaction类型
	if txs, ok := data.([]*MockTransaction); ok {
		if len(txs) > 1 {
			return processAndSave(path, txs)
		}
		data = txs[0]
	}

	// 处理ExecutionResult类型
	if traces, ok := data.([]*ExecutionResult); ok {
		if len(traces) > 1 {
			return processAndSave(path, traces)
		}
		data = traces[0]
	}

	if receipts, ok := data.(types.Receipts); ok {
		if len(receipts) > 1 {
			return processAndSave(path, receipts)
		}
		data = receipts[0]
	}
	// 默认处理
	return encodeJson(path, data)
}

// 通用的处理函数，用于处理数组并生成JSON文件
func processAndSave(path string, dataArray interface{}) error {
	switch data := dataArray.(type) {
	case []*MockTransaction:
		for index, item := range data {
			fileName := fmt.Sprintf("%s_%d%s", path[:len(path)-len(fileSuffix)], index, fileSuffix)
			if err := encodeJson(fileName, item); err != nil {
				return err
			}
		}
	case []*ExecutionResult:
		for index, item := range data {
			fileName := fmt.Sprintf("%s_%d%s", path[:len(path)-len(fileSuffix)], index, fileSuffix)
			if err := encodeJson(fileName, item); err != nil {
				return err
			}
		}
	case types.Receipts:
		for index, item := range data {
			fileName := fmt.Sprintf("%s_%d%s", path[:len(path)-len(fileSuffix)], index, fileSuffix)
			if err := encodeJson(fileName, item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported data type")
	}
	return nil
}

func encodeJson(path string, data interface{}) error {
	result := struct {
		JsonRPC string      `json:"jsonrpc"`
		ID      int         `json:"id"`
		Result  interface{} `json:"result"`
	}{
		JsonRPC: "2.0",
		ID:      1,
		Result:  data,
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(result)
	if err != nil {
		return err
	}
	return nil
}

func ReturnOufOfGas(bytecode string, isCall bool) uint64 {
	fromAddr := "0x000000000000000000000000000000000000cafe"
	toAddr := "0xfefefefefefefefefefefefefefefefefefefefe"
	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress(fromAddr).
			Balance("0x100")
		// to 调用合约
		accs[1].
			FromAddress(toAddr).
			Code(OpcodeToBytes(bytecode)).
			Balance("0x56bc75e2d63100000")
	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(1000000)
	}
	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 1000
	}

	usedGas, err := getGasCost([]string{}, accFuns, txFunc, blockFunc, 2, 1)
	if err != nil {
		fmt.Println("expected error, err", err)
		return uint64(0)
	}

	if isCall {
		return usedGas[toAddr] - 1 - 21000
	}
	return usedGas[toAddr] - 1
}

func getGasCost(
	historyHashes []string,
	accFns func([]*MockAccount),
	funcTx func([]*MockTransaction, []*MockAccount),
	funcBlock func(*MockBlock, []*MockTransaction),
	accountNum int,
	txNum int,
) (UsedGas, error) {
	// 初始化MockAccount
	mockAccounts := make([]*MockAccount, accountNum)
	for i := range mockAccounts {
		mockAccounts[i] = &MockAccount{
			Account: Account{
				Storage: make(map[common.Hash]common.Hash),
			},
		}
	}
	accFns(mockAccounts)

	// 初始化MockTransaction
	mockTransactions := make([]*MockTransaction, txNum)
	for idx := range mockTransactions {
		mockTransactions[idx] = NewMockTransaction()
		mockTransactions[idx].TransactionIndex = uint64(idx)
		mockTransactions[idx].Nonce = uint64(idx)
	}

	funcTx(mockTransactions, mockAccounts)
	for idx := range mockTransactions {
		mockTransactions[idx].Build()
	}

	// 构建Block
	mockBlock := NewMockBlock()
	if len(historyHashes) > 0 {
		mockBlock.SetParentHash(historyHashes[len(historyHashes)-1])
	}
	mockBlock.Transactions = mockTransactions
	funcBlock(mockBlock, mockTransactions)

	accounts := ConvertToAccount(mockAccounts)
	transactions := make([]*Transaction, txNum)
	for idx := range mockTransactions {
		transactions[idx] = mockTransactions[idx].ConvertToTransaction()
	}
	block := mockBlock.ConvertToBlock()

	var historyHashesHexBig []*hexutil.Big
	for _, hash := range historyHashes {
		historyHashesHexBig = append(historyHashesHexBig, hexToHexBig(hash))
	}

	traceConfig := GenerateTraceConfig(transactions, accounts, historyHashesHexBig, block, CHAINID)
	_, useGas, err := Trace(traceConfig)
	if err != nil {
		return nil, err
	}

	return useGas, nil
}
