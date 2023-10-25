package cashier

import (
	"crypto/ecdsa"
	"encoding/binary"
	"math"
	"math/big"
	"strings"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/gcash/bchd/btcjson"
	"github.com/gcash/bchd/chaincfg/chainhash"

	"github.com/elfinguard/chainlogs/bch"
)

func proveCashTokensOwnership(
	bchClient bch.IBchClient,
	privKey *ecdsa.PrivateKey,
	txid string, vout uint32,
) (*CashTokensProof, error) {
	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return nil, err
	}

	mempool := true // ??
	txOut, err := bchClient.GetTxOut(txHash, vout, mempool)
	if err != nil {
		return nil, err
	}

	tokenInfo := txOutToTokenData(txOut)
	tokenInfoBytes := tokenInfoToBytes(tokenInfo)
	sig, err := signBytes(privKey, tokenInfoBytes)
	if err != nil {
		return nil, err
	}

	proof := &CashTokensProof{
		TXID:      txid,
		Vout:      vout,
		TokenInfo: *tokenInfo,
		Sig:       sig,
	}

	return proof, nil
}

func txOutToTokenData(txOut *btcjson.GetTxOutResult) *bch.TokenInfo {
	var addrAndTokenAmt [32]byte
	var tokenId [32]byte
	var nftDataLenAndHead [32]byte
	var nftDataTail [32]byte

	asm := strings.Split(txOut.ScriptPubKey.Asm, " ")
	addr := getAddrFromASM(asm)
	copy(addrAndTokenAmt[0:20], addr)

	amt := utxoAmtToSats(txOut.Value)
	binary.BigEndian.PutUint64(addrAndTokenAmt[24:], amt)

	copy(tokenId[:], gethcmn.Hex2Bytes(txOut.TokenData.Category))

	commitment := gethcmn.Hex2Bytes(txOut.TokenData.Nft.Commitment)
	nftDataLenAndHead[0] = byte(len(commitment))
	nftDataLenAndHead[1] = getNftCap(txOut.TokenData.Nft.Capability)
	if n := len(commitment); n <= 8 {
		copy(nftDataLenAndHead[24:], commitment[:n])
	} else {
		copy(nftDataLenAndHead[24:], commitment[:8])
		copy(nftDataTail[:], commitment[8:])
	}

	return &bch.TokenInfo{
		AddressAndTokenAmount:      big.NewInt(0).SetBytes(addrAndTokenAmt[:]),
		TokenCategory:              big.NewInt(0).SetBytes(tokenId[:]),
		NftCommitmentLengthAndHead: big.NewInt(0).SetBytes(nftDataLenAndHead[:]),
		NftCommitmentTail:          big.NewInt(0).SetBytes(nftDataTail[:]),
	}
}

func getAddrFromASM(asm []string) []byte {
	// P2SH ?
	if len(asm) == 3 &&
		asm[0] == "OP_HASH160" &&
		len(asm[1]) == 40 &&
		asm[2] == "OP_EQUAL" {

		return gethcmn.Hex2Bytes(asm[1])
	}

	// P2PKH ?
	if len(asm) == 5 &&
		asm[0] == "OP_DUP" &&
		asm[1] == "OP_HASH160" &&
		len(asm[2]) == 40 &&
		asm[3] == "OP_EQUALVERIFY" &&
		asm[4] == "OP_CHECKSIG" {

		return gethcmn.Hex2Bytes(asm[2])
	}

	return nil
}

func getNftCap(cap string) byte {
	switch cap {
	case "minting":
		return 3
	case "mutable":
		return 2
	case "none":
		return 1
	default:
		return 0
	}
}

func utxoAmtToSats(amt float64) uint64 {
	return uint64(math.Round(amt * 1e8))
}

func tokenInfoToBytes(tokenInfo *bch.TokenInfo) []byte {
	result := make([]byte, 32*4)
	copy(result[0:32], tokenInfo.AddressAndTokenAmount.Bytes())
	copy(result[32:64], tokenInfo.TokenCategory.Bytes())
	copy(result[64:96], tokenInfo.NftCommitmentLengthAndHead.Bytes())
	copy(result[96:128], tokenInfo.NftCommitmentLengthAndHead.Bytes())
	return result
}
