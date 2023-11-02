package cashier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	eciesgo "github.com/ecies/go/v2"
	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchutil"
	vrf "github.com/vechain/go-ecvrf"

	"github.com/elfinguard/chainlogs/bch"
)

type TokenMetaData struct {
	Amount        uint64 // 8 bytes
	Possibility   uint16 // 2 bytes
	TokenCategory []byte // 32 bytes
	NftCommitment []byte // 40 bytes
}

type ReencryptedDataForTokenOwner struct {
	Data hexutil.Bytes `json:"data"`
}

type ReencryptedDataForPaidUser struct {
	Data     hexutil.Bytes `json:"data"`
	VrfAlpha hexutil.Bytes `json:"vrfAlpha"`
	VrfBeta  hexutil.Bytes `json:"vrfBeta"`
	VrfPi    hexutil.Bytes `json:"vrfPi"`
}

func decryptForTokenOwner(
	bchClient bch.IBchClient,
	privKey *ecdsa.PrivateKey,
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	txid string,
	vout uint32,
) ([]byte, error) {
	// decode & check metadata
	metaData, err := decodeTokenMetaData(encodedMetaData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %d", err)
	}
	if metaData.Possibility != 0 {
		return nil, fmt.Errorf("metadata.possibility is not zero: %d", metaData.Possibility)
	}

	// decrypt & check encrypted data
	eciesPrivKey := toEciesPrivKey(privKey)
	decryptedData, err := eciesgo.Decrypt(eciesPrivKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	if n := len(decryptedData); n <= 32 {
		return nil, fmt.Errorf("decrypted data is too short: %d", n)
	}
	if a, b := decryptedData[:32], sha256.Sum256(encodedMetaData); !bytes.Equal(a, b[:]) {
		return nil, fmt.Errorf("metadata hash not match: %s != %s",
			hex.EncodeToString(a), hex.EncodeToString(b[:]))
	}

	// get utxo data
	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx hash: %w", err)
	}
	mempool := true
	txOut, err := bchClient.GetTxOut(txHash, vout, mempool)
	if err != nil || txOut == nil {
		return nil, fmt.Errorf("failed to get txout: %w", err)
	}
	tokenAmt, err := strconv.ParseUint(txOut.TokenData.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token amount %w", err)
	}

	// check token info
	if a, b := txOut.TokenData.Category, hex.EncodeToString(metaData.TokenCategory); a != b {
		return nil, fmt.Errorf("token category not match: %s != %s", a, b)
	}
	if a, b := txOut.TokenData.Nft.Commitment, hex.EncodeToString(metaData.NftCommitment); a != b {
		return nil, fmt.Errorf("nft commitment not match: %s != %s", a, b)
	}
	if tokenAmt != metaData.Amount {
		return nil, fmt.Errorf("token amount not match: %d != %d", tokenAmt, metaData.Amount)
	}
	if a, b := getAddrFromTxOut(txOut), bchutil.Hash160(reencryptPubKey); !bytes.Equal(a, b) {
		return nil, fmt.Errorf("token owner not match: %s != %s",
			hex.EncodeToString(a), hex.EncodeToString(b))
	}

	// reencrypt data
	eciesPubKey, err := eciesgo.NewPublicKeyFromBytes(reencryptPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECIES pubkey: %w", err)
	}
	reencryptedData, err := eciesgo.Encrypt(eciesPubKey, decryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to reencrypt data: %w", err)
	}

	return reencryptedData, nil
}

func decryptForPaidUser(
	bchClient bch.IBchClient,
	privKey *ecdsa.PrivateKey,
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	rawTx []byte,
) (*ReencryptedDataForPaidUser, error) { // decode & check metadata
	metaData, err := decodeTokenMetaData(encodedMetaData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %d", err)
	}
	if !isAllZero(metaData.TokenCategory) {
		return nil, fmt.Errorf("token category must be zero for now")
	}

	// decrypt & check encrypted data
	eciesPrivKey := toEciesPrivKey(privKey)
	decryptedData, err := eciesgo.Decrypt(eciesPrivKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	if n := len(decryptedData); n <= 32 {
		return nil, fmt.Errorf("decrypted data is too short: %d", n)
	}
	if a, b := decryptedData[32:], sha256.Sum256(encodedMetaData); !bytes.Equal(a, b[:]) {
		return nil, fmt.Errorf("metadata hash not match: %s != %s",
			hex.EncodeToString(a), hex.EncodeToString(b[:]))
	}

	// check tx
	msgTx, err := decodeMsgTx(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rawTx: %w", err)
	}
	txOk := false
	p2pkh := bchutil.Hash160(reencryptPubKey)
	for _, txOut := range msgTx.TxOut {
		if txOut.Value >= int64(metaData.Amount) {
			addr, ok := isP2PKH(txOut.PkScript)
			if ok && bytes.Equal(p2pkh, addr) {
				txOk = true
				break
			}
		}
	}
	if !txOk {
		return nil, fmt.Errorf("invalid tx")
	}

	// test tx
	mempoolTestOk, err := bchClient.TestMempoolAccept(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to call testmempoolaccept: %w", err)
	}
	if !mempoolTestOk {
		return nil, fmt.Errorf("testmempoolaccept returns false")
	}

	// check possibillity & broadcast tx
	txHash := msgTx.TxHash()
	alpha := gethcmn.FromHex(txHash.String())
	beta, pi, err := vrf.Secp256k1Sha256Tai.Prove(privKey, alpha)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VRF random")
	}
	if n := len(beta); n != 32 {
		return nil, fmt.Errorf("invalid beta length: %d", n)
	}
	rand16 := toUint16(beta[30:])
	if rand16 < metaData.Possibility {
		//fmt.Println("txHash:", txHash.String())
		_txHash, err := bchClient.SendRawTransaction(rawTx)
		if err != nil {
			return nil, fmt.Errorf("failed to broadcast tx: %w", err)
		}
		if !_txHash.IsEqual(&txHash) {
			return nil, fmt.Errorf("txHash not match: %s!=%s",
				txHash.String(), _txHash.String())
		}
	}

	// reencrypt data
	eciesPubKey, err := eciesgo.NewPublicKeyFromBytes(reencryptPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECIES pubkey: %w", err)
	}
	reencryptedData, err := eciesgo.Encrypt(eciesPubKey, decryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to reencrypt data: %w", err)
	}

	return &ReencryptedDataForPaidUser{
		Data:     reencryptedData,
		VrfAlpha: alpha,
		VrfBeta:  beta,
		VrfPi:    pi,
	}, nil
}

func decodeTokenMetaData(data []byte) (TokenMetaData, error) {
	if n := len(data); n != 8+2+32+40 {
		return TokenMetaData{}, fmt.Errorf("invalid metadata len: %d", n)
	}
	return TokenMetaData{
		Amount:        uint64(binary.LittleEndian.Uint64(data[0:8])),
		Possibility:   uint16(binary.LittleEndian.Uint16(data[8:10])),
		TokenCategory: data[10:42],
		NftCommitment: data[42:],
	}, nil
}

func toEciesPrivKey(privKey *ecdsa.PrivateKey) *eciesgo.PrivateKey {
	return &eciesgo.PrivateKey{
		PublicKey: &eciesgo.PublicKey{
			Curve: privKey.Curve,
			X:     privKey.X,
			Y:     privKey.Y,
		},
		D: privKey.D,
	}
}

func toEciesPubKey(privKey *ecdsa.PublicKey) *eciesgo.PublicKey {
	return &eciesgo.PublicKey{
		Curve: privKey.Curve,
		X:     privKey.X,
		Y:     privKey.Y,
	}
}

func isAllZero(a []byte) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}
