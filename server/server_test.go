package server

import (
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gcash/bchd/bchec"

	"github.com/elfinguard/cashier/cashier"
	"github.com/elfinguard/chainlogs/bch"
)

const (
	testPrivKey = "9208dfe9750a4e122231d407e801dd35a21347c1cacf436aa423bdbe6db88f58"
)

type MockCashier struct{}

func (m *MockCashier) JudgeStochasticPayment(rawTx []byte) (*cashier.PaymentJudgment, error) {
	return &cashier.PaymentJudgment{
		Prob16:   1234,
		Rand16:   5678,
		VrfAlpha: []byte("alpha"),
		VrfBeta:  []byte("beta"),
		VrfPi:    []byte("pi"),
		LogInfo:  []byte("logInfo"),
		LogSig:   []byte("logSig"),
		// ts:       999,
	}, nil
}

func (m *MockCashier) ProveCashTokensOwnership(txid string, vout uint32) (*cashier.CashTokensProof, error) {
	return &cashier.CashTokensProof{
		TXID:          "1234",
		Vout:          2345,
		Confirmations: 3456,
		Sig:           []byte("sig"),
		TokenData:     []byte("tokenData"),
		TokenInfo: bch.TokenInfo{
			AddressAndTokenAmount:      big.NewInt(1111),
			TokenCategory:              big.NewInt(2222),
			NftCommitmentLengthAndHead: big.NewInt(3333),
			NftCommitmentTail:          big.NewInt(4444),
		},
	}, nil
}

func (m *MockCashier) DecryptForTokenOwner(
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	txid string,
	vout uint32,
) (*cashier.ReencryptedDataForTokenOwner, error) {
	return &cashier.ReencryptedDataForTokenOwner{Data: []byte("abcd")}, nil
}

func (m *MockCashier) DecryptForPaidUser(
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	rawTx []byte,
) (*cashier.ReencryptedDataForPaidUser, error) {
	return &cashier.ReencryptedDataForPaidUser{Data: []byte("efgh")}, nil

}

func init() {
	_privKey, _pubKey := bchec.PrivKeyFromBytes(bchec.S256(), gethcmn.FromHex(testPrivKey))
	pubKeyBytes = _pubKey.SerializeCompressed()
	certBytes = []byte{0xce, 0x27}
	evmAddr = gethcrypto.PubkeyToAddress(_privKey.PublicKey)
	_cashier = &MockCashier{}
}

func TestHandleCert(t *testing.T) {
	require.Equal(t, `{"success":true,"result":"0xce27"}`,
		mustCallHandler("/cert"))
}

func TestHandleCertReport(t *testing.T) {
	//require.True(t, !sgxMode)
	//require.Equal(t, `{"success":false,"error":"non-SGX mode"}`,
	//	mustCallHandler("/cert-report"))
}

func TestHandlePubKey(t *testing.T) {
	require.Equal(t, `{"success":true,"result":"0x02c728b10007959336c10ee4cbb92a1158cf026a3866f6bfca57668d5536180d35"}`,
		mustCallHandler("/pubkey"))
}

func TestHandlePubkeyReport(t *testing.T) {
	//require.True(t, !sgxMode)
	//require.Equal(t, `{"success":false,"error":"non-SGX mode"}`,
	//	mustCallHandler("/pubkey-report"))
}

func TestHandleEvmAddress(t *testing.T) {
	require.Equal(t, `{"success":true,"result":"0x49cafdfef4dccf0a611d612e12630b1c416f1edb"}`,
		mustCallHandler("/evm-address"))
}

func TestHandleJudgeTx(t *testing.T) {
	require.Equal(t, `{"success":false,"error":"missing param: tx"}`,
		mustCallHandler("/judge?tx="))
	//require.Equal(t, `{"success":false,"error":"failed to decode rawTx: unexpected EOF"}`,
	//	mustCallHandler("/judge?tx=0x1234"))

	require.Equal(t, `{"success":true,"result":{"prob16":1234,"rand16":5678,"vrfAlpha":"0x616c706861","vrfBeta":"0x62657461","vrfPi":"0x7069","logInfo":"0x6c6f67496e666f","logSig":"0x6c6f67536967","rawLog":{"chainId":null,"timestamp":null,"address":"0x0000000000000000000000000000000000000000","topics":null,"data":"0x"}}}`,
		mustCallHandler("/judge?tx=0x1234"))
}

func TestHandleProveCashTokens(t *testing.T) {
	require.Equal(t, `{"success":false,"error":"missing param: txid"}`,
		mustCallHandler("/prove-cashtokens"))
	require.Equal(t, `{"success":false,"error":"missing param: vout"}`,
		mustCallHandler("/prove-cashtokens?txid=1234"))
	require.Equal(t, `{"success":true,"result":{"txid":"1234","vout":2345,"confirmations":3456,"tokenInfo":{"addressAndTokenAmount":1111,"tokenCategory":2222,"nftCommitmentLengthAndHead":3333,"nftCommitmentTail":4444},"tokenData":"0x746f6b656e44617461","sig":"0x736967"}}`,
		mustCallHandler("/prove-cashtokens?txid=1234&vout=2"))
}

func TestHandleDecryptForTokenOwner(t *testing.T) {
	require.Equal(t, `{"success":false,"error":"missing param: metadata"}`,
		mustCallHandler("/decrypt-for-token-owner"))
	require.Equal(t, `{"success":false,"error":"missing param: encrypted"}`,
		mustCallHandler("/decrypt-for-token-owner?metadata=1234"))
	require.Equal(t, `{"success":false,"error":"missing param: pubkey"}`,
		mustCallHandler("/decrypt-for-token-owner?metadata=1234&encrypted=2345"))
	require.Equal(t, `{"success":false,"error":"missing param: txid"}`,
		mustCallHandler("/decrypt-for-token-owner?metadata=1234&encrypted=2345&pubkey=3456"))
	require.Equal(t, `{"success":false,"error":"missing param: vout"}`,
		mustCallHandler("/decrypt-for-token-owner?metadata=1234&encrypted=2345&pubkey=3456&txid=4567"))
	require.Equal(t, `{"success":true,"result":{"data":"0x61626364"}}`,
		mustCallHandler("/decrypt-for-token-owner?metadata=1234&encrypted=2345&pubkey=3456&txid=4567&vout=1"))
}

func TestHandleDecryptForPaidUser(t *testing.T) {
	require.Equal(t, `{"success":false,"error":"missing param: metadata"}`,
		mustCallHandler("/decrypt-for-paid-user"))
	require.Equal(t, `{"success":false,"error":"missing param: encrypted"}`,
		mustCallHandler("/decrypt-for-paid-user?metadata=1234"))
	require.Equal(t, `{"success":false,"error":"missing param: pubkey"}`,
		mustCallHandler("/decrypt-for-paid-user?metadata=1234&encrypted=2345"))
	require.Equal(t, `{"success":false,"error":"missing param: tx"}`,
		mustCallHandler("/decrypt-for-paid-user?metadata=1234&encrypted=2345&pubkey=3456"))
	require.Equal(t, `{"success":true,"result":{"data":"0x65666768","vrfAlpha":"0x","vrfBeta":"0x","vrfPi":"0x"}}`,
		mustCallHandler("/decrypt-for-paid-user?metadata=1234&encrypted=2345&pubkey=3456&tx=4567"))
}

func mustCallHandler(path string) string {
	resp, err := callHandler(path)
	if err != nil {
		panic(err)
	}
	return resp
}
func callHandler(path string) (string, error) {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()

	mux := createHttpHandlers()
	mux.ServeHTTP(w, r)

	res := w.Result()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	return string(data), err
}
