package cashier

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
)

// LogInfo is copied from ElfinGuard
type LogInfo struct {
	ChainId   *hexutil.Big   `json:"chainId"`
	Timestamp *hexutil.Big   `json:"timestamp"`
	Address   common.Address `json:"address"`
	Topics    []common.Hash  `json:"topics"`
	Data      hexutil.Bytes  `json:"data"`
}

func (li *LogInfo) ToBytes() []byte {
	bz := make([]byte, 32*2+21, 32*2+21+32*len(li.Topics)+len(li.Data))
	copy(bz[32*0:32*0+32], math.PaddedBigBytes((*big.Int)(li.ChainId), 32))
	copy(bz[32*1:32*1+32], math.PaddedBigBytes((*big.Int)(li.Timestamp), 32))
	copy(bz[32*2:32*2+20], li.Address.Bytes())
	bz[32*2+20] = byte(len(li.Topics))
	for _, t := range li.Topics {
		bz = append(bz, t[:]...)
	}
	bz = append(bz, li.Data...)
	return bz
}

func castTopics(topics [][32]byte) []common.Hash {
	gethTopics := make([]common.Hash, len(topics))
	for i, topic := range topics {
		gethTopics[i] = topic
	}
	return gethTopics
}
