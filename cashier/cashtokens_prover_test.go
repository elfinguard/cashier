package cashier

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gcash/bchd/btcjson"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"

	"github.com/elfinguard/chainlogs/bch"
)

const (
	// b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1:1
	txOut1 = `
  {
    "bestblock": "00000000000000000134fdfb9ca875be0ffa5ace1c9ae4592da61cdffa0677b3",
    "confirmations": 18874,
    "value": 1e-05,
    "scriptPubKey": {
      "asm": "OP_HASH160 f11c46d9edfada19dc967daa9089fe2ae7be4e79 OP_EQUAL",
      "hex": "a914f11c46d9edfada19dc967daa9089fe2ae7be4e7987",
      "reqSigs": 1,
      "type": "scripthash",
      "addresses": [
        "bitcoincash:prc3c3keahad5xwuje764yyflc4w00jw0y4502vsq4"
      ]
    },
    "tokenData": {
      "category": "edbe109abcc7a7509c375379435726748f4ffae819dd582660f752aa1e01bd3f",
      "amount": "4503599626370496",
      "nft": {
        "capability": "none",
        "commitment": "00"
      }
    },
    "coinbase": false
  }
`

	// b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1:8
	txOut2 = `
  {
    "bestblock": "0000000000000000003f385a8c7e6ab5a73c9e2fd0e1d29bf051c5f3adeffc12",
    "confirmations": 18893,
    "value": 1e-05,
    "scriptPubKey": {
      "asm": "OP_DUP OP_HASH160 745dc2d3cd486035e6c65a45dc0ca5c230eb21c7 OP_EQUALVERIFY OP_CHECKSIG",
      "hex": "76a914745dc2d3cd486035e6c65a45dc0ca5c230eb21c788ac",
      "reqSigs": 1,
      "type": "pubkeyhash",
      "addresses": [
        "bitcoincash:qp69mskne4yxqd0xcedythqv5hprp6epcuyfvygcxm"
      ]
    },
    "tokenData": {
      "category": "959d2c30ddc029417fe32e5675b71ecf35260cfd88236411b7fa59e31cd727d4",
      "amount": "13998700000010"
    },
    "coinbase": false
  }
  `

	// 5e293287fd562670a8c2dad479a1338187661c616c8296508817555040b5ba6c:1
	txOut3 = `
  {
    "bestblock": "000000000000000000740f8dc4137a2528de43f090a3d465888c18efc1b4c586",
    "confirmations": 12348,
    "value": 0.00876852,
    "scriptPubKey": {
      "asm": "OP_DUP OP_HASH160 745dc2d3cd486035e6c65a45dc0ca5c230eb21c7 OP_EQUALVERIFY OP_CHECKSIG",
      "hex": "76a914745dc2d3cd486035e6c65a45dc0ca5c230eb21c788ac",
      "reqSigs": 1,
      "type": "pubkeyhash",
      "addresses": [
        "bitcoincash:qp69mskne4yxqd0xcedythqv5hprp6epcuyfvygcxm"
      ]
    },
    "coinbase": false
  }
  `
)

func parseTxOut(data string) *btcjson.GetTxOutResult {
	var txOut btcjson.GetTxOutResult
	_ = json.Unmarshal([]byte(data), &txOut)
	return &txOut
}

func TestTxOutToTokenData_P2PKH(t *testing.T) {
	txOut := parseTxOut(txOut2)
	tokenData, err := txOutToTokenData(txOut)
	require.NoError(t, err)
	require.Equal(t, "745dc2d3cd486035e6c65a45dc0ca5c230eb21c70000000000000cbb538a730a",
		bnToHex(tokenData.AddressAndTokenAmount))
	require.Equal(t, "959d2c30ddc029417fe32e5675b71ecf35260cfd88236411b7fa59e31cd727d4",
		bnToHex(tokenData.TokenCategory))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentLengthAndHead))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentTail))
}

func TestTxOutToTokenData_P2SH(t *testing.T) {
	txOut := parseTxOut(txOut1)
	tokenData, err := txOutToTokenData(txOut)
	require.NoError(t, err)
	require.Equal(t, "f11c46d9edfada19dc967daa9089fe2ae7be4e7900000000000ffffffff0bdc0",
		bnToHex(tokenData.AddressAndTokenAmount))
	require.Equal(t, "edbe109abcc7a7509c375379435726748f4ffae819dd582660f752aa1e01bd3f",
		bnToHex(tokenData.TokenCategory))
	require.Equal(t, "0101000000000000000000000000000000000000000000000000000000000000",
		bnToHex(tokenData.NftCommitmentLengthAndHead))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentTail))
}

func TestProveCashTokensOwnership(t *testing.T) {
	txId := "b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1"
	txHash, err := chainhash.NewHashFromStr(txId)
	require.NoError(t, err)

	mc := &bch.MockClient{}
	mc.AddTxOut(txHash, 1, parseTxOut(txOut1))
	mc.AddTxOut(txHash, 2, parseTxOut(txOut2))
	mc.AddTxOut(txHash, 3, parseTxOut(txOut3))

	r := &Cashier{
		bchClient: mc,
		privKey:   newPrivKey(),
	}

	proof1, err := r.ProveCashTokensOwnership(txId, 1)
	require.NoError(t, err)
	require.NotNil(t, proof1)
	require.Equal(t, txId, proof1.TXID)
	require.Equal(t, uint32(1), proof1.Vout)
	require.Equal(t, int64(18874), proof1.Confirmations)
	require.Equal(t, "f11c46d9edfada19dc967daa9089fe2ae7be4e7900000000000ffffffff0bdc0",
		bnToHex(proof1.TokenInfo.AddressAndTokenAmount))
	require.Equal(t, "f11c46d9edfada19dc967daa9089fe2ae7be4e7900000000000ffffffff0bdc0edbe109abcc7a7509c375379435726748f4ffae819dd582660f752aa1e01bd3f01010000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000",
		hex.EncodeToString(proof1.TokenData))

	proof2, err := r.ProveCashTokensOwnership(txId, 2)
	require.NoError(t, err)
	require.NotNil(t, proof2)
	require.Equal(t, txId, proof2.TXID)
	require.Equal(t, uint32(2), proof2.Vout)
	require.Equal(t, int64(18893), proof2.Confirmations)
	require.Equal(t, "745dc2d3cd486035e6c65a45dc0ca5c230eb21c70000000000000cbb538a730a",
		bnToHex(proof2.TokenInfo.AddressAndTokenAmount))

	proof3, err := r.ProveCashTokensOwnership(txId, 3)
	require.Error(t, err)
	require.Equal(t, "no token data", err.Error())
	require.Nil(t, proof3)

	proof4, err := r.ProveCashTokensOwnership(txId, 4)
	require.Error(t, err)
	require.Equal(t, "no tx out", err.Error())
	require.Nil(t, proof4)
}
