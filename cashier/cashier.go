package cashier

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/txscript"
	"github.com/gcash/bchd/wire"
	"github.com/holiman/uint256"
	vrf "github.com/vechain/go-ecvrf"

	"github.com/elfinguard/chainlogs/bch"
)

const (
	PossibilityByteCount = 2 // bytes
	vBchChainID          = "0x7669727475616c20426974636f696e2043617368000000000000000000000000"
)

type ICashier interface {
	judge(rawTx []byte) (*Judgment, error)
}

type Cashier struct {
	bchClient bch.IBchClient
	privKey   *ecdsa.PrivateKey
}

type Judgment struct {
	Prob16   uint16        `json:"prob16"`
	Rand16   uint16        `json:"rand16"`
	VrfAlpha hexutil.Bytes `json:"vrfAlpha"`
	VrfBeta  hexutil.Bytes `json:"vrfBeta"`
	VrfPi    hexutil.Bytes `json:"vrfPi"`
	LogInfo  hexutil.Bytes `json:"logInfo"`
	LogSig   hexutil.Bytes `json:"logSig"`
	LogRaw   LogInfo       `json:"rawLog"`
	ts       int64
}

func (judger *Cashier) judge(rawTx []byte) (*Judgment, error) {
	return judgeStochasticPayment(judger.bchClient, judger.privKey, rawTx)
}

func judgeStochasticPayment(
	bchClient bch.IBchClient,
	privKey *ecdsa.PrivateKey,
	rawTx []byte,
) (*Judgment, error) {
	msgTx, err := decodeMsgTx(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rawTx: %w", err)
	}

	receiverInfos := getReceiverInfos(msgTx)
	if len(receiverInfos) == 0 {
		return nil, fmt.Errorf("receiver infos not found")
	}

	opRetScript := getOpRetScript(msgTx)
	if len(opRetScript) == 0 {
		return nil, fmt.Errorf("opRet not found")
	}

	contractAddress, topics, otherData, err := bch.ParseEGTXNullData(hex.EncodeToString(opRetScript))
	if err != nil {
		return nil, fmt.Errorf("failed to parse opRet script: %w", err)
	}
	if len(otherData) == 0 {
		return nil, fmt.Errorf("no possibility data")
	}
	if n := len(otherData[0]); n != PossibilityByteCount {
		return nil, fmt.Errorf("invalid possibility data length: %x", n)
	}

	senderInfos, err := getSenderInfos(msgTx, bchClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender infos: %w", err)
	}

	mempoolTestOk, err := bchClient.TestMempoolAccept(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to call testmempoolaccept: %w", err)
	}
	if !mempoolTestOk {
		return nil, fmt.Errorf("testmempoolaccept returns false")
	}

	txHash := msgTx.TxHash()
	alpha := gethcmn.FromHex(txHash.String())
	beta, pi, err := vrf.Secp256k1Sha256Tai.Prove(privKey, alpha)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VRF random")
	}
	if n := len(beta); n != 32 {
		return nil, fmt.Errorf("invalid beta length: %d", n)
	}

	ts := time.Now().Unix()
	data := bch.BuildLogData(uint256.NewInt(0), receiverInfos, senderInfos, nil, nil, otherData)
	logInfo := LogInfo{
		ChainId:   (*hexutil.Big)(big.NewInt(0).SetBytes(gethcmn.FromHex(vBchChainID))),
		Timestamp: (*hexutil.Big)(big.NewInt(ts)),
		Address:   contractAddress,
		Topics:    castTopics(topics),
		Data:      data,
	}
	logBytes := logInfo.ToBytes()
	logSig, err := signBytes(privKey, logBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign logInfo: %w", err)
	}

	judgment := &Judgment{
		Prob16:   toUint16(otherData[0]),
		Rand16:   toUint16(beta[30:]),
		VrfAlpha: alpha,
		VrfBeta:  beta,
		VrfPi:    pi,
		LogInfo:  logBytes,
		LogSig:   logSig,
		LogRaw:   logInfo,
		ts:       ts,
	}

	if judgment.Rand16 < judgment.Prob16 {
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

	return judgment, nil
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

func decodeMsgTx(data []byte) (*wire.MsgTx, error) {
	msg := &wire.MsgTx{}
	err := msg.Deserialize(bytes.NewReader(data))
	return msg, err
}

func getReceiverInfos(tx *wire.MsgTx) (receiverInfos [][32]byte) {
	for _, txOut := range tx.TxOut {
		if pkh, ok := isP2PKH(txOut.PkScript); ok {
			var receiverInfo [32]byte
			copy(receiverInfo[:20], pkh)
			amount := uint256.NewInt(0).Mul(uint256.NewInt(uint64(txOut.Value)), uint256.NewInt(1e10)).Bytes20()
			copy(receiverInfo[20:], amount[8:])
			receiverInfos = append(receiverInfos, receiverInfo)
		}
	}
	return
}

func getOpRetScript(tx *wire.MsgTx) []byte {
	if len(tx.TxOut) == 0 {
		return nil
	}
	if s := tx.TxOut[0].PkScript; isOpRet(s) {
		return s
	}
	return nil
}

// OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
func isP2PKH(pkScript []byte) ([]byte, bool) {
	if len(pkScript) == 25 &&
		pkScript[0] == txscript.OP_DUP &&
		pkScript[1] == txscript.OP_HASH160 &&
		pkScript[23] == txscript.OP_EQUALVERIFY &&
		pkScript[24] == txscript.OP_CHECKSIG {

		return pkScript[3:23], true
	}
	return nil, false
}

// OP_RETURN <data>
func isOpRet(pkScript []byte) bool {
	return len(pkScript) > 1 && pkScript[0] == txscript.OP_RETURN
}

func getSenderInfos(tx *wire.MsgTx, bchClient bch.IBchClient) (senderInfos [][32]byte, _ error) {
	for _, txIn := range tx.TxIn {
		prevTx, err := bchClient.GetRawTransactionVerbose(&txIn.PreviousOutPoint.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to get prev tx: %w", err)
		}
		senderInfo, err := bch.ExtractSenderInfo(prevTx, txIn.PreviousOutPoint.Index, &chaincfg.MainNetParams) // TODO
		if err != nil {
			return nil, fmt.Errorf("failed to extract sender info: %w", err)
		}
		senderInfos = append(senderInfos, senderInfo)
	}
	return
}

func toUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
