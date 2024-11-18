// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evmutil

import (
	"math/big"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/params"
)

var (
	testKey, _           = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testDir              = "test_data"
	blockInfoFileName    = "block_info.json"
	txInfoFileName       = "tx_info.json"
	receiptInfoFileName  = "receipt_info.json"
	txDebugTraceFileName = "tx_debug_trace.json"
	bytecodeFileName     = "bytecode.json"
	fileSuffix           = ".json"
)

// default is LegacyTx -- Eip155
const (
	EIP2930 = 1 // AccessListTx
	EIP1559 = 2 // DynamicFeeTx

	CHAINID = 1337
)

func NewTrace(
	historyHashes []string,
	accFns func([]*MockAccount),
	funcTx func([]*MockTransaction, []*MockAccount),
	funcBlock func(*MockBlock, []*MockTransaction),
	accountNum int,
	txNum int,
	dirName string,
) error {
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
		mockTransactions[idx].BlockNumber = mockBlock.Number
		mockTransactions[idx].BlockHash = mockBlock.Hash
		transactions[idx] = mockTransactions[idx].ConvertToTransaction()
	}
	block := mockBlock.ConvertToBlock()

	var historyHashesHexBig []*hexutil.Big
	for _, hash := range historyHashes {
		historyHashesHexBig = append(historyHashesHexBig, hexToHexBig(hash))
	}

	traceConfig := GenerateTraceConfig(transactions, accounts, historyHashesHexBig, block, CHAINID)
	trace, _, err := Trace(traceConfig)
	if err != nil {
		return err
	}

	var receipts types.Receipts
	for i, tx := range mockTransactions {
		tx_status := uint64(1)
		if trace[i].Failed {
			tx_status = 0
		}
		receipts = append(receipts, &types.Receipt{
			CumulativeGasUsed: trace[i].Gas,
			Bloom:             *mockBlock.LogsBloom,
			Logs:              []*types.Log{},
			Status:            tx_status,
			Type:              uint8(tx.TransactionType),
			TxHash:            tx.Hash,
			TransactionIndex:  uint(i),
			ContractAddress:   *tx.To,
			GasUsed:           trace[i].Gas,
			EffectiveGasPrice: tx.GasPrice,
			BlockHash:         mockBlock.Hash,
			BlockNumber:       big.NewInt(int64(mockBlock.Number)),
		})
	}

	// 把from信息过滤掉
	var outputAccounts []*MockAccount
	for _, acc := range mockAccounts {
		if len(acc.Account.Code) == 0 {
			continue
		}
		outputAccounts = append(outputAccounts, acc)
	}

	// generate files
	dirPath := path.Join(testDir, dirName)
	err = os.MkdirAll(dirPath, 0700)
	if err != nil {
		return err
	}

	// block file
	err = createJson(path.Join(dirPath, blockInfoFileName), mockBlock)
	if err != nil {
		return err
	}

	// tx info
	err = createJson(path.Join(dirPath, txInfoFileName), mockTransactions)
	if err != nil {
		return err
	}

	// receipt info
	err = createJson(path.Join(dirPath, receiptInfoFileName), receipts)
	if err != nil {
		return err
	}

	// trace file
	err = createJson(path.Join(dirPath, txDebugTraceFileName), trace)
	if err != nil {
		return err
	}

	// bytecode file
	err = createJson(path.Join(dirPath, bytecodeFileName), outputAccounts)
	if err != nil {
		return err
	}

	return nil
}

func GenerateTraceConfig(txs []*Transaction, accounts map[common.Address]Account, historyHashes []*hexutil.Big, block Block, chainID uint64) TraceConfig {
	var res TraceConfig

	res.HistoryHashes = historyHashes
	res.Accounts = accounts

	transactions := make([]Transaction, len(txs))
	for id, tx := range txs {
		transactions[id] = *tx
	}
	res.Transactions = transactions

	res.Block = block
	res.ChainID = chainID

	loggerConfig := &logger.Config{
		EnableMemory:     true,
		DisableStack:     false,
		DisableStorage:   false,
		EnableReturnData: true,
	}
	res.LoggerConfig = loggerConfig

	zero := uint64(0)
	chainConfig := &params.ChainConfig{
		ArrowGlacierBlock:             nil,
		ShanghaiTime:                  &zero,
		TerminalTotalDifficulty:       new(big.Int),
		TerminalTotalDifficultyPassed: true,
	}
	res.ChainConfig = chainConfig

	return res
}
