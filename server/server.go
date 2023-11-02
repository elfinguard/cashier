package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/edgelesssys/ego/enclave"
	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
	tmlog "github.com/tendermint/tendermint/libs/log"

	"github.com/elfinguard/chainlogs/bch"
	"github.com/elfinguard/chainlogs/utils"
	"github.com/smartbch/egvm/keygrantor"

	"github.com/elfinguard/cashier/cashier"
)

const (
	HttpsCertFile         = "./key/cert.pem"
	DecryptedHttpsKeyFile = "./key/decryptedKey.pem"
)

var (
	pubKeyBytes []byte
	certBytes   []byte
	evmAddr     gethcmn.Address

	_cashier cashier.ICashier
)

func StartServer(keyGrantor, listenAddr, bchRpcClientInfo string) {
	// load private key from disk
	privKey, err := getPrivKey(keyGrantor)
	if err != nil {
		log.Fatal("failed to load private key: ", err)
	}
	pubKeyBytes = gethcrypto.FromECDSAPub(&privKey.PublicKey)

	// create BCH RPC client
	bchClient := bch.NewRetryableClient(bchRpcClientInfo, 5, 3, tmlog.NewNopLogger())
	_, err = bchClient.GetBlockCount() // test BCH RPC client
	if err != nil {
		log.Fatal("failed to test BCH RPC client: ", err)
	}

	// create payment judger
	_cashier = cashier.NewCashier(bchClient, privKey)
	evmAddr = gethcrypto.PubkeyToAddress(privKey.PublicKey)
	log.Info("evm address: ", evmAddr.String())

	// start HTTPS server
	go startHttpsServer(listenAddr)
	//go startHttpServer(listenAddr) // TODO: change to HTTPS in production mode
	log.Info("server started: ", listenAddr)
	select {}
}

func startHttpServer(listenAddr string) {
	mux := createHttpHandlers()
	err := http.ListenAndServe(listenAddr, mux)
	if err != nil {
		log.Fatal("failed to start HTTP server: ", err)
	}
}

func startHttpsServer(listenAddr string) {
	certificate, err := LoadCertAndDecryptedKey(HttpsCertFile, DecryptedHttpsKeyFile)
	if err != nil {
		log.Errorf("Failed to load encrypted https key and certificate: %v", err)
		return
	}

	mux := createHttpHandlers()
	server := http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{certificate}},
	}
	//log.Info("listening at:", listenAddr, "...")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("failed to start HTTPS server: ", err)
	}
}

func createHttpHandlers() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/cert", handleCert)
	mux.HandleFunc("/cert-report", handleCertReport)
	mux.HandleFunc("/pubkey", handlePubKey)
	mux.HandleFunc("/pubkey-report", handlePubkeyReport)
	mux.HandleFunc("/evm-address", handleEvmAddress)
	mux.HandleFunc("/judge", handleJudgeTx)
	mux.HandleFunc("/prove-cashtokens", handleProveCashTokens)
	mux.HandleFunc("/decrypt-for-token-owner", handleDecryptForTokenOwner)
	mux.HandleFunc("/decrypt-for-paid-user", handleDecryptForPaidUser)
	return mux
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	if utils.GetQueryParam(r, "raw") != "" {
		_, _ = w.Write(certBytes)
		return
	}
	NewOkResp("0x" + hex.EncodeToString(certBytes)).WriteTo(w)
}

func handleCertReport(w http.ResponseWriter, r *http.Request) {
	//if !sgxMode {
	//	NewErrResp("non-SGX mode").WriteTo(w)
	//	return
	//}

	certHash := sha256.Sum256(certBytes)
	report, err := enclave.GetRemoteReport(certHash[:])
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}

	if utils.GetQueryParam(r, "raw") != "" {
		_, _ = w.Write(report)
		return
	}
	NewOkResp("0x" + hex.EncodeToString(report)).WriteTo(w)
}

func handlePubKey(w http.ResponseWriter, r *http.Request) {
	if utils.GetQueryParam(r, "raw") != "" {
		_, _ = w.Write(pubKeyBytes)
		return
	}
	NewOkResp("0x" + hex.EncodeToString(pubKeyBytes)).WriteTo(w)
}

func handlePubkeyReport(w http.ResponseWriter, r *http.Request) {
	//if !sgxMode {
	//	NewErrResp("non-SGX mode").WriteTo(w)
	//	return
	//}

	pbkHash := sha256.Sum256(pubKeyBytes)
	report, err := enclave.GetRemoteReport(pbkHash[:])
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}

	if utils.GetQueryParam(r, "raw") != "" {
		_, _ = w.Write(report)
		return
	}
	NewOkResp("0x" + hex.EncodeToString(report)).WriteTo(w)
}

func handleEvmAddress(w http.ResponseWriter, r *http.Request) {
	NewOkResp(evmAddr).WriteTo(w)
}

func handleJudgeTx(w http.ResponseWriter, r *http.Request) {
	rawTxHex := utils.GetQueryParam(r, "tx")
	if rawTxHex == "" {
		NewErrResp("missing param: tx").WriteTo(w)
		return
	}

	rawTx := gethcmn.FromHex(rawTxHex)
	judgment, err := _cashier.JudgeStochasticPayment(rawTx)
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}
	NewOkResp(judgment).WriteTo(w)
}

func handleProveCashTokens(w http.ResponseWriter, r *http.Request) {
	txid := utils.GetQueryParam(r, "txid")
	if txid == "" {
		NewErrResp("missing param: txid").WriteTo(w)
		return
	}

	vout := utils.GetQueryParam(r, "vout")
	if vout == "" {
		NewErrResp("missing param: vout").WriteTo(w)
		return
	}

	index, err := strconv.ParseUint(vout, 10, 32)
	if err != nil {
		NewErrResp("invalid param: vout").WriteTo(w)
		return
	}

	proof, err := _cashier.ProveCashTokensOwnership(txid, uint32(index))
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}
	NewOkResp(proof).WriteTo(w)
}

func handleDecryptForTokenOwner(w http.ResponseWriter, r *http.Request) {
	metaData := utils.GetQueryParam(r, "metadata")
	if metaData == "" {
		NewErrResp("missing param: metaData").WriteTo(w)
		return
	}

	encryptedData := utils.GetQueryParam(r, "encrypted")
	if encryptedData == "" {
		NewErrResp("missing param: encrypted").WriteTo(w)
		return
	}

	pubkeyData := utils.GetQueryParam(r, "pubkey")
	if pubkeyData == "" {
		NewErrResp("missing param: pubkey").WriteTo(w)
		return
	}

	txid := utils.GetQueryParam(r, "txid")
	if txid == "" {
		NewErrResp("missing param: txid").WriteTo(w)
		return
	}

	vout := utils.GetQueryParam(r, "vout")
	if vout == "" {
		NewErrResp("missing param: vout").WriteTo(w)
		return
	}
	index, err := strconv.ParseUint(vout, 10, 32)
	if err != nil {
		NewErrResp("invalid param: vout").WriteTo(w)
		return
	}

	result, err := _cashier.DecryptForTokenOwner(
		gethcmn.FromHex(metaData),
		gethcmn.FromHex(encryptedData),
		gethcmn.FromHex(pubkeyData),
		txid,
		uint32(index),
	)
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}
	NewOkResp(result).WriteTo(w)
}

func handleDecryptForPaidUser(w http.ResponseWriter, r *http.Request) {
	metaData := utils.GetQueryParam(r, "metadata")
	if metaData == "" {
		NewErrResp("missing param: metaData").WriteTo(w)
		return
	}

	encryptedData := utils.GetQueryParam(r, "encrypted")
	if encryptedData == "" {
		NewErrResp("missing param: encrypted").WriteTo(w)
		return
	}

	pubkeyData := utils.GetQueryParam(r, "pubkey")
	if pubkeyData == "" {
		NewErrResp("missing param: pubkey").WriteTo(w)
		return
	}

	rawTx := utils.GetQueryParam(r, "tx")
	if rawTx == "" {
		NewErrResp("missing param: tx").WriteTo(w)
		return
	}

	result, err := _cashier.DecryptForPaidUser(
		gethcmn.FromHex(metaData),
		gethcmn.FromHex(encryptedData),
		gethcmn.FromHex(pubkeyData),
		gethcmn.FromHex(rawTx),
	)
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}
	NewOkResp(result).WriteTo(w)
}

func getPrivKey(keyGrantor string) (*ecdsa.PrivateKey, error) {
	log.Info("get key from KeyGrantor:", keyGrantor)
	key, err := keygrantor.GetKeyFromKeyGrantor(keyGrantor, [32]byte{})
	if err != nil {
		return nil, err
	}
	return gethcrypto.ToECDSA(key.Key)
}
