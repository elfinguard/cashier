package server

import (
	"crypto/tls"
	"os"

	"github.com/edgelesssys/ego/ecrypto"
)

func LoadCertAndDecryptedKey(certFile, decryptedKeyFile string) (tls.Certificate, error) {
	return loadCert(certFile, decryptedKeyFile, false)
}

func loadCert(certFile, httpsKeyFile string, isEnclaveMode bool) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := os.ReadFile(httpsKeyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if isEnclaveMode {
		keyPEMBlock, err = ecrypto.Unseal(keyPEMBlock, nil)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}
