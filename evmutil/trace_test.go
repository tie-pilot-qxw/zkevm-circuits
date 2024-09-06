// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evmutil

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"os"
	"testing"
)

func TestInnerCallJumpInvalid(t *testing.T) {
	b, err := os.ReadFile("./test_data/example.json")
	if err != nil {
		t.Fatal(err)
	}
	var traceConfig TraceConfig
	err = json.Unmarshal(b, &traceConfig)
	if err != nil {
		t.Fatal(err)
	}
	trace, _, err := Trace(traceConfig)
	if err != nil {
		t.Fatal(err)
	}
	marshal, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(marshal))
}

func TestRootInvalidJump(t *testing.T) {
	calleeOpcode := `
PUSH1 0x1
PUSH1 0x1
JUMP
PUSH1 0x0
PUSH1 0x0
JUMPDEST
STOP
`

	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress("0x000000000000000000000000000000000000cafe").
			Balance("0x8ac7230489e80000")
		// to 调用合约
		accs[1].
			FromAddress("0xffffffffffffffffffffffffffffffffffffffff").
			Code(OpcodeToBytes(calleeOpcode)).
			Balance("0x56bc75e2d63100000")

	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(100000)
	}

	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 100
	}

	err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 2, 1, "root_invalid_jump")
	if err != nil {
		t.Fatal("expected error, err", err)
	}
}

func TestSubCallInvalidJump(t *testing.T) {
	callerOpcode := `
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
PUSH2 0x2710
CALL
STOP
`
	calleeOpcode := `
PUSH1 0x1
PUSH1 0x1
JUMP
PUSH1 0x0
PUSH1 0x0
JUMPDEST
STOP
`
	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress("0x000000000000000000000000000000000000cafe").
			Balance("0x8ac7230489e80000")
		// to 调用合约
		accs[1].
			FromAddress("0xfefefefefefefefefefefefefefefefefefefefe").
			Code(OpcodeToBytes(callerOpcode)).
			Balance("0x56bc75e2d63100000")
		// 子合约账户
		accs[2].
			FromAddress("0xffffffffffffffffffffffffffffffffffffffff").
			Code(OpcodeToBytes(calleeOpcode)).
			Balance("0x56bc75e2d63100000")
	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(100000)
	}

	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 1
	}

	err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 3, 1, "sub_call_invalid_jump")
	if err != nil {
		t.Fatal("expected error, err", err)
	}
}

func TestRootOutOfGasExp(t *testing.T) {
	bytecode := `
PUSH1 0x1
PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
EXP
`

	gas := ReturnOufOfGas(bytecode, false)
	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress("0x000000000000000000000000000000000000cafe").
			Balance("0x100")
		// to 调用合约
		accs[1].
			FromAddress("0xfefefefefefefefefefefefefefefefefefefefe").
			Code(OpcodeToBytes(bytecode)).
			Balance("0x56bc75e2d63100000")
	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(gas)
	}
	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 1000
	}

	err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 2, 1, "root_exp_out_of_gas")
	if err != nil {
		t.Fatal("expected error, err", err)
	}
}

func TestSubCallOutOfGasExp(t *testing.T) {
	calleeOpcode := `
PUSH1 0x1
PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
EXP
`
	gas := ReturnOufOfGas(calleeOpcode, true)

	callerOpcode := fmt.Sprintf(`
	PUSH1 0x0
	PUSH1 0x0
	PUSH1 0x0
	PUSH1 0x0
	PUSH1 0x0
	PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
	PUSH1 %s
	CALL
	STOP
`, hexutil.Uint64(gas).String())

	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress("0x000000000000000000000000000000000000cafe").
			Balance("0x8ac7230489e80000")
		// to 调用合约
		accs[1].
			FromAddress("0xfefefefefefefefefefefefefefefefefefefefe").
			Code(OpcodeToBytes(callerOpcode))
		// 子合约账户
		accs[2].
			FromAddress("0xffffffffffffffffffffffffffffffffffffffff").
			Code(OpcodeToBytes(calleeOpcode))
	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(1000000)
	}

	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 1
	}

	err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 3, 1, "sub_call_out_of_gas_exp")
	if err != nil {
		t.Fatal("expected error, err", err)
	}
}

func TestCallNoExec(t *testing.T) {
	callerOpcode := `
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
PUSH2 0x2710
CALL
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x0
PUSH1 0x100
PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
PUSH2 0x2710
CALL
JUMP
STOP
`
	calleeOpcode := `
PUSH1 0x1
PUSH1 0x1
STOP
`

	accFuns := func(accs []*MockAccount) {
		// mock一个账户，也即from
		accs[0].
			FromAddress("0x000000000000000000000000000000000000cafe").
			Balance("0x100")
		// to 调用合约
		accs[1].
			FromAddress("0xfefefefefefefefefefefefefefefefefefefefe").
			Code(OpcodeToBytes(callerOpcode)).
			Balance("0x56bc75e2d63100000")
		// 子合约账户
		accs[2].
			FromAddress("0xffffffffffffffffffffffffffffffffffffffff").
			Code(OpcodeToBytes(calleeOpcode)).
			Balance("0x56bc75e2d63100000")
	}

	txFunc := func(txs []*MockTransaction, accs []*MockAccount) {
		txs[0].
			FromAddress(accs[0].Address).
			ToAddress(accs[1].Address).
			SetGas(100000)
	}

	blockFunc := func(block *MockBlock, txs []*MockTransaction) {
		block.Number = 1000
	}

	err := NewTrace([]string{}, accFuns, txFunc, blockFunc, 3, 1, "call_no_execution")
	if err != nil {
		t.Fatal("expected error, err", err)
	}
}
