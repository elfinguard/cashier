package cashier

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"

	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func newPrivKey() *ecdsa.PrivateKey {
	privKey, _ := gethcrypto.GenerateKey()
	return privKey
}

func hexToByte32(s string) (s32 [32]byte) {
	copy(s32[:], gethcmn.FromHex(s))
	return
}

func bnToHex(n *big.Int) string {
	return hex.EncodeToString(n.Bytes())
}

func toJSON(v any) string {
	result, _ := json.MarshalIndent(v, "", "  ")
	return string(result)
}
