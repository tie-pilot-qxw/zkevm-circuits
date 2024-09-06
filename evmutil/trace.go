// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package evmutil

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"dario.cat/mergo"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
	"github.com/ethereum/go-ethereum/params"
)

type ExecutionResult struct {
	Gas         uint64          `json:"gas"`
	Failed      bool            `json:"failed"`
	ReturnValue string          `json:"returnValue"`
	StructLogs  []StructLogRes  `json:"structLogs"`
	Prestate    json.RawMessage `json:"prestate"`
	CallTrace   json.RawMessage `json:"callTrace"`
}

// StructLogRes 不包含ReturnData
type StructLogRes struct {
	Pc            uint64             `json:"pc"`
	Op            string             `json:"op"`
	Gas           uint64             `json:"gas"`
	GasCost       uint64             `json:"gasCost"`
	Depth         int                `json:"depth"`
	Error         string             `json:"error,omitempty"`
	Stack         *[]string          `json:"stack,omitempty"`
	Memory        *[]string          `json:"memory,omitempty"`
	Storage       *map[string]string `json:"storage,omitempty"`
	RefundCounter uint64             `json:"refund,omitempty"`
}

// FormatLogs 没有return_data 因为return_data的值通过外部别的函数获取
func FormatLogs(logs []logger.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:            trace.Pc,
			Op:            trace.Op.String(),
			Gas:           trace.Gas,
			GasCost:       trace.GasCost,
			Depth:         trace.Depth,
			Error:         trace.ErrorString(),
			RefundCounter: trace.RefundCounter,
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = stackValue.Hex()
			}
			formatted[index].Stack = &stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = &memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = &storage
		}
	}
	return formatted
}

type TraceConfig struct {
	ChainID uint64 `json:"chain_id"`
	// HistoryHashes contains most recent 256 block hashes in history,
	// where the lastest one is at HistoryHashes[len(HistoryHashes)-1].
	HistoryHashes []*hexutil.Big             `json:"history_hashes"`
	Block         Block                      `json:"block_constants"`
	Accounts      map[common.Address]Account `json:"accounts"`
	Transactions  []Transaction              `json:"transactions"`
	LoggerConfig  *logger.Config             `json:"logger_config"`
	ChainConfig   *params.ChainConfig        `json:"chain_config"`
}

type UsedGas map[string]uint64

func Trace(config TraceConfig) ([]*ExecutionResult, UsedGas, error) {
	chainConfig := params.ChainConfig{
		ChainID:             new(big.Int).SetUint64(config.ChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
	}

	if config.ChainConfig != nil {
		mergo.Merge(&chainConfig, config.ChainConfig, mergo.WithOverride)
	}

	var txsGasLimit uint64
	blockGasLimit := hexBigToBigInt(config.Block.GasLimit).Uint64()
	messages := make([]core.Message, len(config.Transactions))
	usedGas := make(UsedGas)
	for i, tx := range config.Transactions {
		if tx.GasPrice != nil {
			// Set GasFeeCap and GasTipCap to GasPrice if not exist.
			if tx.GasFeeCap == nil {
				tx.GasFeeCap = tx.GasPrice
			}
			if tx.GasTipCap == nil {
				tx.GasTipCap = tx.GasPrice
			}
		}

		txAccessList := make(types.AccessList, len(tx.AccessList))
		for i, accessList := range tx.AccessList {
			txAccessList[i].Address = accessList.Address
			txAccessList[i].StorageKeys = accessList.StorageKeys
		}
		messages[i] = core.Message{
			From:              tx.From,
			To:                tx.To,
			Nonce:             uint64(tx.Nonce),
			Value:             hexBigToBigInt(tx.Value),
			GasLimit:          uint64(tx.GasLimit),
			GasPrice:          hexBigToBigInt(tx.GasPrice),
			GasFeeCap:         hexBigToBigInt(tx.GasFeeCap),
			GasTipCap:         hexBigToBigInt(tx.GasTipCap),
			Data:              tx.CallData,
			AccessList:        txAccessList,
			SkipAccountChecks: false,
		}

		txsGasLimit += uint64(tx.GasLimit)
	}
	if txsGasLimit > blockGasLimit {
		return nil, usedGas, fmt.Errorf("txs total gas: %d Exceeds block gas limit: %d", txsGasLimit, blockGasLimit)
	}

	prevrandao := common.BigToHash(hexBigToBigInt(config.Block.MixHash))

	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash: func(n uint64) common.Hash {
			number := config.Block.Number.ToInt().Uint64()
			if number > n && number-n <= 256 {
				index := uint64(len(config.HistoryHashes)) - number + n
				return common.BigToHash(hexBigToBigInt(config.HistoryHashes[index]))
			}
			return common.Hash{}
		},
		Coinbase:    config.Block.Coinbase,
		BlockNumber: hexBigToBigInt(config.Block.Number),
		Time:        hexBigToBigInt(config.Block.Timestamp).Uint64(),
		Difficulty:  hexBigToBigInt(config.Block.Difficulty),
		Random:      &prevrandao,
		BaseFee:     hexBigToBigInt(config.Block.BaseFee),
		GasLimit:    blockGasLimit,
	}

	// Setup state db with accounts from argument
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	for address, account := range config.Accounts {
		stateDB.SetNonce(address, uint64(account.Nonce))
		stateDB.SetCode(address, account.Code)
		if account.Balance != nil {
			stateDB.SetBalance(address, hexBigToBigInt(account.Balance))
		}
		for key, value := range account.Storage {
			stateDB.SetState(address, key, value)
		}
	}
	stateDB.Finalise(true)

	// Run the transactions with tracing enabled.
	executionResults := make([]*ExecutionResult, len(config.Transactions))
	for i, message := range messages {
		txContext := core.NewEVMTxContext(&message)
		prestateTracer, err := tracers.DefaultDirectory.New("prestateTracer", new(tracers.Context), nil)
		if err != nil {
			return nil, usedGas, fmt.Errorf("Failed to create prestateTracer: %w", err)
		}
		callTracer, err := tracers.DefaultDirectory.New("callTracer", new(tracers.Context), nil)
		if err != nil {
			return nil, usedGas, fmt.Errorf("Failed to create callTracer: %w", err)
		}
		structLogger := logger.NewStructLogger(config.LoggerConfig)
		tracer := NewMuxTracer(
			structLogger,
			prestateTracer,
			callTracer,
		)
		evm := vm.NewEVM(blockCtx, txContext, stateDB, &chainConfig, vm.Config{Tracer: tracer, NoBaseFee: true})

		result, err := core.ApplyMessage(evm, &message, new(core.GasPool).AddGas(message.GasLimit))
		if err != nil {
			return nil, usedGas, fmt.Errorf("Failed to apply config.Transactions[%d]: %w", i, err)
		}

		usedGas[strings.ToLower(message.To.String())] = result.UsedGas
		stateDB.Finalise(true)

		prestate, err := prestateTracer.GetResult()
		if err != nil {
			return nil, usedGas, fmt.Errorf("Failed to get prestateTracer result: %w", err)
		}

		callTrace, err := callTracer.GetResult()
		if err != nil {
			return nil, usedGas, fmt.Errorf("Failed to get callTracer result: %w", err)
		}

		executionResults[i] = &ExecutionResult{
			Gas:         result.UsedGas,
			Failed:      result.Failed(),
			ReturnValue: fmt.Sprintf("%x", result.ReturnData),
			StructLogs:  FormatLogs(structLogger.StructLogs()),
			Prestate:    prestate,
			CallTrace:   callTrace,
		}
	}

	return executionResults, usedGas, nil
}

type MuxTracer struct {
	tracers []vm.EVMLogger
}

func NewMuxTracer(tracers ...vm.EVMLogger) *MuxTracer {
	return &MuxTracer{tracers}
}

func (t *MuxTracer) CaptureTxStart(gasLimit uint64) {
	for _, tracer := range t.tracers {
		tracer.CaptureTxStart(gasLimit)
	}
}

func (t *MuxTracer) CaptureTxEnd(restGas uint64) {
	for _, tracer := range t.tracers {
		tracer.CaptureTxEnd(restGas)
	}
}

func (t *MuxTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	for _, tracer := range t.tracers {
		tracer.CaptureStart(env, from, to, create, input, gas, value)
	}
}

func (t *MuxTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureEnd(output, gasUsed, err)
	}
}

func (t *MuxTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	for _, tracer := range t.tracers {
		tracer.CaptureEnter(typ, from, to, input, gas, value)
	}
}

func (t *MuxTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureExit(output, gasUsed, err)
	}
}

func (t *MuxTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureState(pc, op, gas, cost, scope, rData, depth, err)
	}
}

func (t *MuxTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureFault(pc, op, gas, cost, scope, depth, err)
	}
}
