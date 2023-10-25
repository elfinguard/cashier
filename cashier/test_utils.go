package cashier

import (
	"encoding/hex"
	"math/big"

	gethcmn "github.com/ethereum/go-ethereum/common"
)

func hexToByte32(s string) (s32 [32]byte) {
	copy(s32[:], gethcmn.FromHex(s))
	return
}

func bnToHex(n *big.Int) string {
	return hex.EncodeToString(n.Bytes())
}
