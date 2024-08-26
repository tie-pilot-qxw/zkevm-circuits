// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evm_util

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

type BlockNonce [8]byte

type Block struct {
	Coinbase   common.Address `json:"coinbase"`
	Timestamp  *hexutil.Big   `json:"timestamp"`
	Number     *hexutil.Big   `json:"number"`
	Difficulty *hexutil.Big   `json:"difficulty"`
	GasLimit   *hexutil.Big   `json:"gas_limit"`
	BaseFee    *hexutil.Big   `json:"base_fee"`
}

type MockBlock struct {
	Hash             common.Hash        // 区块哈希
	ParentHash       common.Hash        // 父区块哈希
	UnclesHash       common.Hash        // 叔块哈希
	Author           common.Address     // 区块作者地址
	StateRoot        common.Hash        // 状态根
	TransactionsRoot common.Hash        // 交易根
	ReceiptsRoot     common.Hash        // 收据根
	Number           uint64             // 区块号
	GasUsed          *big.Int           // 使用的Gas
	GasLimit         *big.Int           // Gas上限
	BaseFeePerGas    *big.Int           // 基础Gas费用
	ExtraData        []byte             // 附加数据
	LogsBloom        *types.Bloom       // 日志Bloom过滤器
	Timestamp        *big.Int           // 时间戳
	Difficulty       *big.Int           // 难度
	TotalDifficulty  *big.Int           // 总难度
	SealFields       [][]byte           // Seal字段
	Uncles           []common.Hash      // 叔块列表
	Transactions     []*MockTransaction // 交易列表
	Size             *big.Int           // 区块大小
	MixHash          common.Hash        // 混合哈希
	Nonce            BlockNonce         // 随机数
	ChainID          uint64             // 链ID
}

func NewMockBlock() *MockBlock {
	return &MockBlock{
		GasUsed:         big.NewInt(0),
		GasLimit:        new(big.Int).SetInt64(0x2386f26fc10000),
		BaseFeePerGas:   big.NewInt(0),
		Timestamp:       timeStamp().ToInt(),
		Difficulty:      big.NewInt(0),
		TotalDifficulty: big.NewInt(0),
		Size:            big.NewInt(0),
		ChainID:         CHAINID,
		Nonce:           BlockNonce{},
		LogsBloom:       &types.Bloom{},
		Uncles:          []common.Hash{},
		Transactions:    []*MockTransaction{},
	}
}

func (b *MockBlock) SetParentHash(hash string) {
	// 设置Parent Hash的方法
	b.Hash = common.HexToHash(hash)
}

func (b *MockBlock) Build() MockBlock {
	return *b
}

func (b *MockBlock) ConvertToBlock() Block {
	// 将MockBlock转换为Block
	return Block{
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Timestamp:  bigIntToHexBig(b.Timestamp),
		Number:     bigIntToHexBig(new(big.Int).SetUint64(b.Number)),
		Difficulty: bigIntToHexBig(b.Difficulty),
		GasLimit:   bigIntToHexBig(b.GasLimit),
		BaseFee:    bigIntToHexBig(b.BaseFeePerGas),
	}
}

type blockJson struct {
	Hash             common.Hash        `json:"hash"`
	ParentHash       common.Hash        `json:"parentHash"`
	UnclesHash       common.Hash        `json:"sha3Uncles"`
	StateRoot        common.Hash        `json:"stateRoot"`
	TransactionsRoot common.Hash        `json:"transactionsRoot"`
	ReceiptsRoot     common.Hash        `json:"receiptsRoot"`
	Number           hexutil.Uint64     `json:"number"`
	GasUsed          *hexutil.Big       `json:"gasUsed"`
	GasLimit         *hexutil.Big       `json:"gasLimit"`
	ExtraData        hexutil.Bytes      `json:"extraData"`
	LogsBloom        *types.Bloom       `json:"logsBloom"`
	Timestamp        *hexutil.Big       `json:"timestamp"`
	Difficulty       *hexutil.Big       `json:"difficulty"`
	TotalDifficulty  *hexutil.Big       `json:"totalDifficulty"`
	Uncles           []common.Hash      `json:"uncles"`
	Transactions     []*MockTransaction `json:"transactions"`
	Size             *hexutil.Big       `json:"size"`
	MixHash          common.Hash        `json:"mixHash"`
	Nonce            hexutil.Bytes      `json:"nonce"`
	BaseFeePerGas    *hexutil.Big       `json:"baseFeePerGas"`
	Author           common.Address     `json:"miner"`
}

func (b *MockBlock) MarshalJSON() ([]byte, error) {
	return json.Marshal(blockJson{
		Hash:             b.Hash,
		ParentHash:       b.ParentHash,
		UnclesHash:       b.UnclesHash,
		StateRoot:        b.StateRoot,
		TransactionsRoot: b.TransactionsRoot,
		ReceiptsRoot:     b.ReceiptsRoot,
		Number:           hexutil.Uint64(b.Number),
		GasUsed:          (*hexutil.Big)(b.GasUsed),
		GasLimit:         (*hexutil.Big)(b.GasLimit),
		ExtraData:        b.ExtraData,
		LogsBloom:        b.LogsBloom,
		Timestamp:        (*hexutil.Big)(b.Timestamp),
		Difficulty:       (*hexutil.Big)(b.Difficulty),
		TotalDifficulty:  (*hexutil.Big)(b.TotalDifficulty),
		Uncles:           b.Uncles,
		Transactions:     b.Transactions,
		Size:             (*hexutil.Big)(b.Size),
		MixHash:          b.MixHash,
		Nonce:            b.Nonce[:],
		BaseFeePerGas:    (*hexutil.Big)(b.BaseFeePerGas),
		Author:           b.Author,
	})
}

func (b *MockBlock) UnmarshalJSON(data []byte) error {
	var block blockJson
	if err := json.Unmarshal(data, &block); err != nil {
		return err
	}
	b.Hash = block.Hash
	b.ParentHash = block.ParentHash
	b.UnclesHash = block.UnclesHash
	b.StateRoot = block.StateRoot
	b.TransactionsRoot = block.TransactionsRoot
	b.ReceiptsRoot = block.ReceiptsRoot
	b.Number = uint64(block.Number)
	b.GasUsed = (*big.Int)(block.GasUsed)
	b.GasLimit = (*big.Int)(block.GasLimit)
	b.ExtraData = block.ExtraData
	b.LogsBloom = block.LogsBloom
	b.Timestamp = (*big.Int)(block.Timestamp)
	b.Difficulty = (*big.Int)(block.Difficulty)
	b.TotalDifficulty = (*big.Int)(block.TotalDifficulty)
	b.Uncles = block.Uncles
	b.Transactions = block.Transactions
	b.Size = (*big.Int)(block.Size)
	b.MixHash = block.MixHash
	b.BaseFeePerGas = (*big.Int)(block.BaseFeePerGas)
	b.Author = block.Author
	copy(b.Nonce[:], block.Nonce)

	return nil
}
