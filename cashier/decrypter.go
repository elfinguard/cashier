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
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchutil"

	"github.com/elfinguard/chainlogs/bch"
)

type MetaData struct {
	Amount        uint64 // 8 bytes
	Possibility   uint16 // 2 bytes
	TokenCategory []byte // 32 bytes
	NftCommitment []byte // 40 bytes
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
	metaData, err := decodeMetaData(encodedMetaData)
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
	if a, b := decryptedData[32:], sha256.Sum256(encodedMetaData); !bytes.Equal(a, b[:]) {
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
) ([]byte, error) { // decode & check metadata
	metaData, err := decodeMetaData(encodedMetaData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %d", err)
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

	// test tx
	mempoolTestOk, err := bchClient.TestMempoolAccept(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to call testmempoolaccept: %w", err)
	}
	if !mempoolTestOk {
		return nil, fmt.Errorf("testmempoolaccept returns false")
	}

	// check tx
	msgTx, err := decodeMsgTx(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rawTx: %w", err)
	}
	// TODO
	fmt.Println(metaData, msgTx)

	// TODO:
	// check possibillity
	// broadcast tx

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

func decodeMetaData(data []byte) (MetaData, error) {
	if n := len(data); n != 8+2+32+40 {
		return MetaData{}, fmt.Errorf("invalid metadata len: %d", n)
	}
	return MetaData{
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
