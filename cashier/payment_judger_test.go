package cashier

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gcash/bchd/btcjson"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/holiman/uint256"

	"github.com/elfinguard/chainlogs/bch"
)

var (
	// https://blockchair.com/bitcoin-cash/transaction/c1d33d4c03c81f8dee2f176b944bc05eb08524163698d4d397a8fb9ca7cd2651
	rawTx1 = "020000000147c8c5a1f4d7d5e3846a7e945daf634722340f617be0ff8736e668d7ee7d9fb402000000644128fd33544f9530b1a8ae03340bdfe9385324adf0ecefc39d53e6fddf9afdb64ccf3ef12bc692045d87e90380919429d3c5bafc29b51515aa0a992dd0d085663e4121031c60b05831b6f3c31739856575cde27d97d9fe926a63d51abce4a0c16b4108be00000000030000000000000000666a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a40000000000110270000000000001976a9148097f6fbaa0dfdfe4f064bb650324c5e8018242088acca331e00000000001976a914307f40d73e01af33364901d82d5614e370f905d388ac00000000"

	// rawTx1 + possibility data
	rawTx2 = strings.Replace(rawTx1, "666a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001",
		"6a6a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a4000000000010002aabb", -1)

	// https://blockchair.com/bitcoin-cash/transaction/b49f7deed768e63687ffe07b610f34224763af5d947e6a84e3d5d7f4a1c5c847
	prevTx = `{
    "txid": "b49f7deed768e63687ffe07b610f34224763af5d947e6a84e3d5d7f4a1c5c847",
    "hash": "b49f7deed768e63687ffe07b610f34224763af5d947e6a84e3d5d7f4a1c5c847",
    "version": 2,
    "size": 330,
    "locktime": 0,
    "vin": [
        {
            "txid": "04f704acf658e36bf0b68f8a99647488ce20f78069ef0712212bcd3b56dc8175",
            "vout": 0,
            "scriptSig": {
                "asm": "4bb6f874b8abde696e413da62404f89f8dcb85d4e1dbdd0800d73263dcaa539b735386bcd745d27ae70c96748f9119151de999a34cd0bcce6f665f8e4999ac1a[ALL|FORKID] 031c60b05831b6f3c31739856575cde27d97d9fe926a63d51abce4a0c16b4108be",
                "hex": "414bb6f874b8abde696e413da62404f89f8dcb85d4e1dbdd0800d73263dcaa539b735386bcd745d27ae70c96748f9119151de999a34cd0bcce6f665f8e4999ac1a4121031c60b05831b6f3c31739856575cde27d97d9fe926a63d51abce4a0c16b4108be"
            },
            "sequence": 0
        }
    ],
    "vout": [
        {
            "value": 0,
            "n": 0,
            "scriptPubKey": {
                "asm": "OP_RETURN 1481918277 56eb561cb6f98a985f80464fa99267a462c91bdb e94358e473941de2d75d19fa330d607e05ffab42 efc507fb38cbcae3b32d1777e54593bc07eca5a1 4ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001",
                "hex": "6a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001",
                "type": "nulldata"
            }
        },
        {
            "value": 0.0001,
            "n": 1,
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 8097f6fbaa0dfdfe4f064bb650324c5e80182420 OP_EQUALVERIFY OP_CHECKSIG",
                "hex": "76a9148097f6fbaa0dfdfe4f064bb650324c5e8018242088ac",
                "reqSigs": 1,
                "type": "pubkeyhash",
                "addresses": [
                    "bitcoincash:qzqf0ahm4gxlmlj0qe9mv5pjf30gqxpyyq00tttfxk"
                ]
            }
        },
        {
            "value": 0.01989669,
            "n": 2,
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 307f40d73e01af33364901d82d5614e370f905d3 OP_EQUALVERIFY OP_CHECKSIG",
                "hex": "76a914307f40d73e01af33364901d82d5614e370f905d388ac",
                "reqSigs": 1,
                "type": "pubkeyhash",
                "addresses": [
                    "bitcoincash:qqc87sxh8cq67vekfyqast2kzn3hp7g96v5upxsa32"
                ]
            }
        }
    ]
}`
)

func createMockBchClient(t *testing.T) *bch.MockClient {
	prevTxId, err := chainhash.NewHashFromStr("b49f7deed768e63687ffe07b610f34224763af5d947e6a84e3d5d7f4a1c5c847")
	require.NoError(t, err)

	var prevTxResult btcjson.TxRawResult
	err = json.Unmarshal([]byte(prevTx), &prevTxResult)
	require.NoError(t, err)

	mc := &bch.MockClient{}
	mc.AddTx(prevTxId, &prevTxResult)
	return mc
}

func TestJudger_decodeMsgTxErr(t *testing.T) {
	r := &Cashier{}
	_, err := r.JudgeStochasticPayment([]byte{1, 2, 3, 4, 5, 6})
	require.ErrorContains(t, err, "failed to decode rawTx")
}

func TestJudger_noReceiversErr(t *testing.T) {
	r := &Cashier{}
	rawTx := strings.Replace(rawTx1, "76a914", "a97614", -1)
	_, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.ErrorContains(t, err, "receiver infos not found")
}

func TestJudger_noOpRetErr(t *testing.T) {
	r := &Cashier{}
	rawTx := strings.Replace(rawTx1, "6a0445475458", "6b0445475458", -1)
	_, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.ErrorContains(t, err, "opRet not found")
}

func TestJudger_parseOpRetErr(t *testing.T) {
	r := &Cashier{}
	rawTx := strings.Replace(rawTx1, "6a0445475458", "6a0445475459", -1)
	_, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.ErrorContains(t, err, "failed to parse opRet script")
}

func TestJudger_possibilityErr(t *testing.T) {
	r := &Cashier{}
	_, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx1))
	require.ErrorContains(t, err, "no possibility data")

	rawTx := strings.Replace(rawTx1, "666a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001",
		"6b6a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a4000000000010003aabbcc", -1)
	_, err = r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.ErrorContains(t, err, "invalid possibility data length: 3")

	rawTx = strings.Replace(rawTx1, "666a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001",
		"696a04454754581456eb561cb6f98a985f80464fa99267a462c91bdb14e94358e473941de2d75d19fa330d607e05ffab4214efc507fb38cbcae3b32d1777e54593bc07eca5a1204ea5c508a6566e76240543f8feb06fd457777be300005af3107a4000000000010001aa", -1)
	_, err = r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.ErrorContains(t, err, "invalid possibility data length: 1")
}

func TestJudger_mempoolTestErr(t *testing.T) {
	r := &Cashier{
		bchClient: createMockBchClient(t),
	}
	_, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx2))
	require.ErrorContains(t, err, "testmempoolaccept returns false")
}

func TestJudger_notBroadcastTx(t *testing.T) {
	txId := "54cdbaf3b7960cdfd2234dfc182ec9b1a5d25febbcda1f333534db50363789f1"
	rawTx := strings.Replace(rawTx2, "aabb", "0000", -1) // possibility = 0
	mc := createMockBchClient(t)
	mc.AddTxToAccept(rawTx)

	r := &Cashier{
		bchClient: mc,
		privKey:   newPrivKey(),
	}
	judgement, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.NoError(t, err)
	require.Equal(t, txId, hex.EncodeToString(judgement.VrfAlpha))
	require.Len(t, judgement.VrfBeta, 32)
	require.NotNil(t, judgement.VrfPi)
	require.NotNil(t, judgement.LogInfo)
	require.NotNil(t, judgement.LogSig)
}

func TestJudger_broadcastTx(t *testing.T) {
	rawTx := strings.Replace(rawTx2, "aabb", "ffff", -1) // possibility = 100%
	txHash, err := chainhash.NewHashFromStr("b459e626435d1b9a52493027975d4c56698b8b70451f484ce6621c1c87ff1881")
	require.NoError(t, err)

	mc := createMockBchClient(t)
	mc.AddTxToAccept(rawTx)
	mc.AddTxToSend(rawTx, txHash)

	r := &Cashier{
		bchClient: mc,
		privKey:   newPrivKey(),
	}
	judgement, err := r.JudgeStochasticPayment(gethcmn.FromHex(rawTx))
	require.NoError(t, err)
	require.Equal(t, txHash.String(), hex.EncodeToString(judgement.VrfAlpha))
	require.Len(t, judgement.VrfBeta, 32)
	require.NotNil(t, judgement.VrfPi)
	require.NotNil(t, judgement.LogInfo)
	require.NotNil(t, judgement.LogSig)

	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], judgement.Rand16)
	require.True(t, bytes.HasSuffix(judgement.VrfBeta, buf[:]))

	topics := [][32]byte{
		hexToByte32("000000000000000000000000e94358e473941de2d75d19fa330d607e05ffab42"),
		hexToByte32("000000000000000000000000efc507fb38cbcae3b32d1777e54593bc07eca5a1"),
		hexToByte32("4ea5c508a6566e76240543f8feb06fd457777be300005af3107a400000000001"),
	}
	receiverInfos := [][32]byte{
		hexToByte32("8097f6fbaa0dfdfe4f064bb650324c5e801824200000000000005af3107a4000"),
		hexToByte32("307f40d73e01af33364901d82d5614e370f905d300000000004651f967cde800"),
	}
	senderInfos := [][32]byte{
		hexToByte32("307f40d73e01af33364901d82d5614e370f905d3000000000046afef23a7f400"),
	}
	otherData := [][]byte{
		gethcmn.FromHex("ffff"),
	}
	data := bch.BuildLogData(uint256.NewInt(0), receiverInfos, senderInfos, nil, nil, otherData)
	logInfo := LogInfo{
		ChainId:   (*hexutil.Big)(big.NewInt(0).SetBytes(gethcmn.FromHex(vBchChainID))),
		Timestamp: (*hexutil.Big)(big.NewInt(judgement.ts)),
		Address:   gethcmn.HexToAddress("56eb561cb6f98a985f80464fa99267a462c91bdb"),
		Topics:    castTopics(topics),
		Data:      data,
	}
	require.Equal(t, hex.EncodeToString(logInfo.ToBytes()), hex.EncodeToString(judgement.LogInfo))
	// TODO: check logSig
}

func TestIsP2PKH(t *testing.T) {
	pbk, ok := isP2PKH(gethcmn.FromHex("76a914307f40d73e01af33364901d82d5614e370f905d388ac"))
	require.True(t, ok)
	require.Equal(t, "307f40d73e01af33364901d82d5614e370f905d3", hex.EncodeToString(pbk))
}

func TestIsOpRet(t *testing.T) {
	ok := isOpRet(gethcmn.FromHex("6a0445475458"))
	require.True(t, ok)
}
