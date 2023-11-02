package cashier

import (
	"bytes"
	"crypto/sha256"
	"testing"

	eciesgo "github.com/ecies/go/v2"
	"github.com/elfinguard/chainlogs/bch"
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
	// eciesPrivKey := toEciesPrivKey(ecdsaPrivKey)
	eciesPubKey := toEciesPubKey(ecdsaPubKey)

	mockBchClient := &bch.MockClient{}
	encodedMetaData := []byte("aaaaaaaa\000\000ccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddd")
	metaDataHash := sha256.Sum256(encodedMetaData)
	secretData := append(metaDataHash[:], []byte("secret")...)
	encryptedData, err := eciesgo.Encrypt(eciesPubKey, secretData)
	require.NoError(t, err)
	// fmt.Println("encodedMetaData:", hex.EncodeToString(encodedMetaData))
	// fmt.Println("metaDataHash:", hex.EncodeToString(metaDataHash[:]))

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

	// TODO
}

func TestDecryptForPaidUser(t *testing.T) {
	// TODO
}
