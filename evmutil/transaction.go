// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evmutil

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

type Transaction struct {
	From       common.Address      `json:"from"`
	To         *common.Address     `json:"to"`
	Nonce      hexutil.Uint64      `json:"nonce"`
	Value      *hexutil.Big        `json:"value"`
	GasLimit   hexutil.Uint64      `json:"gas_limit"`
	GasPrice   *hexutil.Big        `json:"gas_price"`
	GasFeeCap  *hexutil.Big        `json:"gas_fee_cap"`
	GasTipCap  *hexutil.Big        `json:"gas_tip_cap"`
	CallData   hexutil.Bytes       `json:"call_data"`
	AccessList []types.AccessTuple `json:"access_list"`
}

type MockTransaction struct {
	Hash                 common.Hash      // 交易哈希
	Nonce                uint64           // 交易Nonce
	BlockHash            common.Hash      // 区块哈希
	BlockNumber          uint64           // 区块号
	TransactionIndex     uint64           // 交易索引
	From                 common.Address   // 发送方地址或钱包
	To                   *common.Address  // 接收方地址或钱包（可选）
	Value                *big.Int         // 转移的价值
	GasPrice             *big.Int         // Gas价格（可选）
	Gas                  uint64           // Gas数量
	Input                []byte           // 输入数据
	V                    uint64           // 签名参数V（可选）
	R                    *big.Int         // 签名参数R（可选）
	S                    *big.Int         // 签名参数S（可选）
	TransactionType      uint64           // 交易类型
	AccessList           types.AccessList // 访问列表
	MaxPriorityFeePerGas *big.Int         // 最大优先费用
	MaxFeePerGas         *big.Int         // 最大费用
	ChainID              *big.Int         // 链ID
}

func NewMockTransaction() *MockTransaction {
	return &MockTransaction{
		Value:                big.NewInt(0),
		GasPrice:             big.NewInt(0),
		ChainID:              big.NewInt(CHAINID),
		AccessList:           []types.AccessTuple{},
		MaxFeePerGas:         big.NewInt(0),
		MaxPriorityFeePerGas: big.NewInt(0),
	}
}

func (t *MockTransaction) Build() MockTransaction {
	var tx *types.Transaction

	switch t.TransactionType {
	case EIP1559:
		config := params.ChainConfig{
			ChainID:     t.ChainID,
			LondonBlock: big.NewInt(3),
		}
		tx, _ = types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID:    t.ChainID,
			Nonce:      t.Nonce,
			To:         t.To,
			Value:      t.Value,
			Gas:        t.Gas,
			Data:       t.Input,
			GasFeeCap:  big.NewInt(0),
			GasTipCap:  big.NewInt(0),
			AccessList: t.AccessList,
		}), types.LatestSigner(&config), testKey)
	case EIP2930:
		config := params.ChainConfig{
			ChainID:     t.ChainID,
			BerlinBlock: big.NewInt(2),
		}
		tx, _ = types.SignTx(types.NewTx(&types.AccessListTx{
			ChainID:    t.ChainID,
			Nonce:      t.Nonce,
			To:         t.To,
			Value:      t.Value,
			Gas:        t.Gas,
			GasPrice:   t.GasPrice,
			Data:       t.Input,
			AccessList: t.AccessList,
		}), types.LatestSigner(&config), testKey)
	default:
		config := params.ChainConfig{
			ChainID:     t.ChainID,
			EIP155Block: big.NewInt(1),
		}
		tx, _ = types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    t.Nonce,
			To:       t.To,
			Value:    t.Value,
			Gas:      t.Gas,
			GasPrice: t.GasPrice,
			Data:     t.Input,
		}), types.LatestSigner(&config), testKey)
	}

	v, r, s := tx.RawSignatureValues()

	t.V = v.Uint64()
	t.R = r
	t.S = s

	return *t
}

func (t *MockTransaction) ConvertToTransaction() *Transaction {
	return &Transaction{
		From:       t.From,
		To:         t.To,
		Nonce:      uint64ToHexUint64(t.Nonce),
		Value:      bigIntToHexBig(t.Value),
		GasLimit:   uint64ToHexUint64(t.Gas),
		GasPrice:   bigIntToHexBig(t.GasPrice),
		GasFeeCap:  bigIntToHexBig(t.MaxFeePerGas),
		GasTipCap:  bigIntToHexBig(t.MaxPriorityFeePerGas),
		CallData:   t.Input,
		AccessList: t.AccessList,
	}
}

func (t *MockTransaction) FromAddress(address common.Address) *MockTransaction {
	t.From = address
	return t
}

func (t *MockTransaction) ToAddress(address common.Address) *MockTransaction {
	addr := address
	t.To = &addr
	return t
}

func (t *MockTransaction) SetGas(gas uint64) *MockTransaction {
	t.Gas = gas
	return t
}

type txJson struct {
	Hash                 common.Hash      `json:"hash"`
	Nonce                hexutil.Uint64   `json:"nonce"`
	BlockHash            common.Hash      `json:"blockHash"`
	BlockNumber          hexutil.Uint64   `json:"blockNumber"`
	TransactionIndex     hexutil.Uint64   `json:"transactionIndex"`
	From                 common.Address   `json:"from"`
	To                   *common.Address  `json:"to"`
	Value                *hexutil.Big     `json:"value"`
	GasPrice             *hexutil.Big     `json:"gasPrice"`
	Gas                  hexutil.Uint64   `json:"gas"`
	Input                hexutil.Bytes    `json:"input"`
	V                    hexutil.Uint64   `json:"v"`
	R                    *hexutil.Big     `json:"r"`
	S                    *hexutil.Big     `json:"s"`
	ChainID              *hexutil.Big     `json:"chainId"`
	TransactionType      hexutil.Uint64   `json:"type"`
	AccessList           types.AccessList `json:"accessList"`
	MaxFeePerGas         *hexutil.Big     `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big     `json:"maxPriorityFeePerGas"`
}

func (t *MockTransaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(txJson{
		Hash:                 t.Hash,
		Nonce:                hexutil.Uint64(t.Nonce),
		BlockHash:            t.BlockHash,
		BlockNumber:          hexutil.Uint64(t.BlockNumber),
		TransactionIndex:     hexutil.Uint64(t.TransactionIndex),
		From:                 t.From,
		To:                   t.To,
		Value:                (*hexutil.Big)(t.Value),
		GasPrice:             (*hexutil.Big)(t.GasPrice),
		Gas:                  hexutil.Uint64(t.Gas),
		Input:                t.Input,
		V:                    hexutil.Uint64(t.V),
		R:                    (*hexutil.Big)(t.R),
		S:                    (*hexutil.Big)(t.S),
		ChainID:              (*hexutil.Big)(t.ChainID),
		TransactionType:      hexutil.Uint64(t.TransactionType),
		AccessList:           t.AccessList,
		MaxFeePerGas:         (*hexutil.Big)(t.MaxFeePerGas),
		MaxPriorityFeePerGas: (*hexutil.Big)(t.MaxPriorityFeePerGas),
	})
}

func (t *MockTransaction) UnmarshalJSON(input []byte) error {
	var tx txJson
	if err := json.Unmarshal(input, &tx); err != nil {
		return err
	}
	t.Hash = tx.Hash
	t.Nonce = uint64(tx.Nonce)
	t.BlockHash = tx.BlockHash
	t.BlockNumber = uint64(tx.BlockNumber)
	t.TransactionIndex = uint64(tx.TransactionIndex)
	t.From = tx.From
	t.To = tx.To
	t.Value = (*big.Int)(tx.Value)
	t.GasPrice = (*big.Int)(tx.GasPrice)
	t.Gas = uint64(tx.Gas)
	t.Input = tx.Input
	t.V = uint64(tx.V)
	t.R = (*big.Int)(tx.R)
	t.S = (*big.Int)(tx.S)
	t.ChainID = (*big.Int)(tx.ChainID)
	t.TransactionType = uint64(tx.TransactionType)
	t.AccessList = tx.AccessList
	t.MaxFeePerGas = (*big.Int)(tx.MaxFeePerGas)
	t.MaxPriorityFeePerGas = (*big.Int)(tx.MaxPriorityFeePerGas)
	return nil
}
