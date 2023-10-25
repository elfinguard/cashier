package cashier

import (
	"encoding/json"
	"testing"

	"github.com/gcash/bchd/btcjson"
	"github.com/stretchr/testify/require"
)

func TestTxOutToTokenData_P2PKH(t *testing.T) {
	// b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1:8
	txOutJSON := `
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

	var txOut btcjson.GetTxOutResult
	require.NoError(t, json.Unmarshal([]byte(txOutJSON), &txOut))

	tokenData := txOutToTokenData(&txOut)
	require.Equal(t, "745dc2d3cd486035e6c65a45dc0ca5c230eb21c70000000000000000000003e8",
		bnToHex(tokenData.AddressAndTokenAmount))
	require.Equal(t, "959d2c30ddc029417fe32e5675b71ecf35260cfd88236411b7fa59e31cd727d4",
		bnToHex(tokenData.TokenCategory))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentLengthAndHead))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentTail))
}

func TestTxOutToTokenData_P2SH(t *testing.T) {
	// b277d9b5fda9713fc12b38f1e9c7728cf84e3b60c00f0ea4c28191dddc9770a1:1
	txOutJSON := `
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

	var txOut btcjson.GetTxOutResult
	require.NoError(t, json.Unmarshal([]byte(txOutJSON), &txOut))

	tokenData := txOutToTokenData(&txOut)
	require.Equal(t, "f11c46d9edfada19dc967daa9089fe2ae7be4e790000000000000000000003e8",
		bnToHex(tokenData.AddressAndTokenAmount))
	require.Equal(t, "edbe109abcc7a7509c375379435726748f4ffae819dd582660f752aa1e01bd3f",
		bnToHex(tokenData.TokenCategory))
	require.Equal(t, "0101000000000000000000000000000000000000000000000000000000000000",
		bnToHex(tokenData.NftCommitmentLengthAndHead))
	require.Equal(t, "", bnToHex(tokenData.NftCommitmentTail))
}
