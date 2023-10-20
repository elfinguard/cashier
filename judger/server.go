package judger

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/enclave"
	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
	tmlog "github.com/tendermint/tendermint/libs/log"

	"github.com/elfinguard/chainlogs/bch"
	"github.com/elfinguard/chainlogs/utils"
	"github.com/elfinhost/elfinhost-lab/certs"
	"github.com/elfinhost/elfinhost-lab/keygrantor"
)

const (
	HttpsCertFile         = "./key/cert.pem"
	DecryptedHttpsKeyFile = "./key/decryptedKey.pem"
)

var (
	pubKeyBytes []byte
	certBytes   []byte
	evmAddr     gethcmn.Address

	judger IPaymentJudger
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
	judger = &BchStochasticPaymentJudger{
		bchClient: bchClient,
		privKey:   privKey,
	}
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
	certificate, err := certs.LoadCertAndDecryptedKey(HttpsCertFile, DecryptedHttpsKeyFile)
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
	judgment, err := judger.judge(rawTx)
	if err != nil {
		NewErrResp(err.Error()).WriteTo(w)
		return
	}
	NewOkResp(judgment).WriteTo(w)
}

func getPrivKey(keyGrantor string) (*ecdsa.PrivateKey, error) {
	log.Info("get key from KeyGrantor:", keyGrantor)
	key, err := keygrantor.GetKeyFromKeyGrantor(keyGrantor, [32]byte{})
	if err != nil {
		return nil, err
	}
	return gethcrypto.ToECDSA(key.Key)
}
