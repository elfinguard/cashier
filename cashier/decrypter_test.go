package cashier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	eciesgo "github.com/ecies/go/v2"
	"github.com/elfinguard/chainlogs/bch"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gcash/bchd/btcjson"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchutil"
	"github.com/stretchr/testify/require"
)

func TestDecodeTokenMetaData(t *testing.T) {
	encodedMetaData := []byte("aaaaaaaabbccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddd")
	metaData, err := decodeTokenMetaData(encodedMetaData)
	require.NoError(t, err)
	require.Equal(t, uint64(0x6161616161616161), metaData.Amount)
	require.Equal(t, uint16(0x6262), metaData.Possibility)
	require.Equal(t, "cccccccccccccccccccccccccccccccc", string(metaData.TokenCategory))
	require.Equal(t, "dddddddddddddddddddddddddddddddddddddddd", string(metaData.NftCommitment))
}

func TestDecryptForTokenOwner(t *testing.T) {
	ecdsaPrivKey := newPrivKey()
	ecdsaPubKey := &ecdsaPrivKey.PublicKey
	pubKeyBytes := gethcrypto.FromECDSAPub(ecdsaPubKey)
	pubKeyHash := bchutil.Hash160(pubKeyBytes)
	// eciesPrivKey := toEciesPrivKey(ecdsaPrivKey)
	eciesPubKey := toEciesPubKey(ecdsaPubKey)

	encodedMetaData := []byte("aaaaaaaa\000\000ccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddd")
	metaDataHash := sha256.Sum256(encodedMetaData)
	secretData := append(metaDataHash[:], []byte("secret")...)
	encryptedData, err := eciesgo.Encrypt(eciesPubKey, secretData)
	require.NoError(t, err)
	// fmt.Println("encodedMetaData:", hex.EncodeToString(encodedMetaData))
	// fmt.Println("metaDataHash:", hex.EncodeToString(metaDataHash[:]))

	mockBchClient := &bch.MockClient{}
	txId := "b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1"
	txHash, _ := chainhash.NewHashFromStr(txId)
	mockBchClient.AddTxOut(txHash, 0, &btcjson.GetTxOutResult{})
	mockBchClient.AddTxOut(txHash, 1, &btcjson.GetTxOutResult{
		TokenData: btcjson.TokenDataResult{Amount: "123"},
	})
	mockBchClient.AddTxOut(txHash, 2, &btcjson.GetTxOutResult{
		TokenData: btcjson.TokenDataResult{
			Amount: "7016996765293437281",
		},
	})
	mockBchClient.AddTxOut(txHash, 3, &btcjson.GetTxOutResult{
		TokenData: btcjson.TokenDataResult{
			Amount:   "7016996765293437281",
			Category: hex.EncodeToString([]byte("cccccccccccccccccccccccccccccccc")),
		},
	})
	mockBchClient.AddTxOut(txHash, 4, &btcjson.GetTxOutResult{
		TokenData: btcjson.TokenDataResult{
			Amount:   "7016996765293437281",
			Category: hex.EncodeToString([]byte("cccccccccccccccccccccccccccccccc")),
			Nft: btcjson.NftResult{
				Commitment: hex.EncodeToString([]byte("dddddddddddddddddddddddddddddddddddddddd")),
			},
		},
	})
	mockBchClient.AddTxOut(txHash, 5, &btcjson.GetTxOutResult{
		TokenData: btcjson.TokenDataResult{
			Amount:   "7016996765293437281",
			Category: hex.EncodeToString([]byte("cccccccccccccccccccccccccccccccc")),
			Nft: btcjson.NftResult{
				Commitment: hex.EncodeToString([]byte("dddddddddddddddddddddddddddddddddddddddd")),
			},
		},
		ScriptPubKey: btcjson.ScriptPubKeyResult{
			Asm: "OP_DUP OP_HASH160 " + hex.EncodeToString(pubKeyHash) + " OP_EQUALVERIFY OP_CHECKSIG",
		},
	})

	metaDataTooShort := []byte("too_short")
	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		metaDataTooShort, encryptedData, nil, "txid", 0)
	require.ErrorContains(t, err, "failed to decode metadata")

	metaDataTooLong := append(encodedMetaData, 1)
	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		metaDataTooLong, encryptedData, nil, "txid", 0)
	require.ErrorContains(t, err, "failed to decode metadata")

	possibilityGt0 := bytes.ReplaceAll(encodedMetaData, []byte{0, 0}, []byte{1, 2})
	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		possibilityGt0, encryptedData, nil, "txid", 0)
	require.ErrorContains(t, err, "metadata.possibility is not zero")

	decryptedToShort, err := eciesgo.Encrypt(eciesPubKey, []byte("too short"))
	require.NoError(t, err)
	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, decryptedToShort, nil, "txid", 0)
	require.ErrorContains(t, err, "decrypted data is too short")

	changedMetaData := bytes.ReplaceAll(encodedMetaData, []byte("aaa"), []byte("xxx"))
	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		changedMetaData, encryptedData, nil, "txid", 0)
	require.ErrorContains(t, err, "metadata hash not match")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, "txid", 0)
	require.ErrorContains(t, err, "failed to parse tx hash")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 123)
	require.ErrorContains(t, err, "failed to get txout")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 0)
	require.ErrorContains(t, err, "failed to parse token amount")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 1)
	require.ErrorContains(t, err, "token amount not match")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 2)
	require.ErrorContains(t, err, "token category not match")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 3)
	require.ErrorContains(t, err, "nft commitment not match")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, nil, txId, 4)
	require.ErrorContains(t, err, "token owner not match")

	_, err = decryptForTokenOwner(mockBchClient, ecdsaPrivKey,
		encodedMetaData, encryptedData, pubKeyBytes, txId, 5)
	require.NoError(t, err)
}

func TestDecryptForPaidUser(t *testing.T) {
	// TODO
}
