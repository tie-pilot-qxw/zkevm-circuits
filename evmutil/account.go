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
)

type Account struct {
	Nonce   hexutil.Uint64
	Balance *hexutil.Big
	Code    hexutil.Bytes
	Storage map[common.Hash]common.Hash
}

type MockAccount struct {
	Address common.Address
	Account
}

func ConvertToAccount(accounts []*MockAccount) map[common.Address]Account {
	res := make(map[common.Address]Account)
	for _, acc := range accounts {
		res[acc.Address] = acc.Account
	}
	return res
}

func (a *MockAccount) FromAddress(address string) *MockAccount {
	addr := common.HexToAddress(address)
	a.Address = addr
	return a
}

func (a *MockAccount) Code(bytes []byte) *MockAccount {
	a.Account.Code = bytes
	return a
}

func (a *MockAccount) Nonce(nonce hexutil.Uint64) *MockAccount {
	a.Account.Nonce = nonce
	return a
}

func (a *MockAccount) Balance(balance string) *MockAccount {
	a.Account.Balance = hexToHexBig(balance)
	return a
}

type accountJson struct {
	Bytecode        hexutil.Bytes               `json:"bytecode"`
	ContractAddress common.Address              `json:"contract_addr"`
	Storage         map[common.Hash]common.Hash `json:"storage"`
}

func (a *MockAccount) MarshalJSON() ([]byte, error) {
	return json.Marshal(&accountJson{
		Bytecode:        a.Account.Code,
		ContractAddress: a.Address,
		Storage:         a.Storage,
	})
}

func (a *MockAccount) UnmarshalJSON(input []byte) error {
	var jsonAccount accountJson
	if err := json.Unmarshal(input, &jsonAccount); err != nil {
		return err
	}
	a.Account.Code = jsonAccount.Bytecode
	a.Address = jsonAccount.ContractAddress
	a.Storage = jsonAccount.Storage
	return nil
}
