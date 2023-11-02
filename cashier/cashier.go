package cashier

import (
	"crypto/ecdsa"
	"fmt"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/elfinguard/chainlogs/bch"
)

const (
	PossibilityByteCount = 2 // bytes
	vBchChainID          = "0x7669727475616c20426974636f696e2043617368000000000000000000000000"
)

type ICashier interface {
	JudgeStochasticPayment(rawTx []byte) (*PaymentJudgment, error)
	ProveCashTokensOwnership(txid string, vout uint32) (*CashTokensProof, error)
	DecryptForTokenOwner(encodedMetaData []byte, encryptedData []byte, reencryptPubKey []byte,
		txid string, vout uint32) ([]byte, error)
	DecryptForPaidUser(encodedMetaData []byte, encryptedData []byte, reencryptPubKey []byte,
		rawTx []byte) (*ReencryptedDataForPaidUser, error)
}

type Cashier struct {
	bchClient bch.IBchClient
	privKey   *ecdsa.PrivateKey
}

func NewCashier(bchClient bch.IBchClient, privKey *ecdsa.PrivateKey) *Cashier {
	return &Cashier{
		bchClient: bchClient,
		privKey:   privKey,
	}
}

func (c *Cashier) JudgeStochasticPayment(rawTx []byte) (*PaymentJudgment, error) {
	return judgeStochasticPayment(c.bchClient, c.privKey, rawTx)
}

func (c *Cashier) ProveCashTokensOwnership(txid string, vout uint32) (*CashTokensProof, error) {
	mempool := true // TODO
	return proveCashTokensOwnership(c.bchClient, c.privKey, txid, vout, mempool)
}

func (c *Cashier) DecryptForTokenOwner(
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	txid string,
	vout uint32,
) ([]byte, error) {
	return decryptForTokenOwner(c.bchClient, c.privKey,
		encodedMetaData, encodedMetaData, reencryptPubKey, txid, vout)
}

func (c *Cashier) DecryptForPaidUser(
	encodedMetaData []byte,
	encryptedData []byte,
	reencryptPubKey []byte,
	rawTx []byte,
) (*ReencryptedDataForPaidUser, error) {
	return decryptForPaidUser(c.bchClient, c.privKey,
		encodedMetaData, encodedMetaData, reencryptPubKey, rawTx)
}

// Endorse a message by signing it with privKey
func signBytes(privKey *ecdsa.PrivateKey, message []byte) (sig []byte, err error) {
	msgHash := gethcrypto.Keccak256Hash(message)
	ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgHash[:]), msgHash[:])
	ethMsgHash := gethcrypto.Keccak256Hash([]byte(ethMsg))

	sig, err = gethcrypto.Sign(ethMsgHash[:], privKey)
	if err == nil {
		// v=27|28 instead of 0|1...
		sig[len(sig)-1] += 27
	}
	return
}
