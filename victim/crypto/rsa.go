package crypto

import (
	"crypto/rsa"
	"crypto/tls"
	"math/big"
)

// Section: Public Key Retrieval
func FetchPublicKey(serverAddress string) (*rsa.PublicKey, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConnection, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer tlsConnection.Close()

	peerCertificates := tlsConnection.ConnectionState().PeerCertificates
	return peerCertificates[0].PublicKey.(*rsa.PublicKey), nil
}

// Section: RSA Encryption (PKCS#1 v1.5)
func EncryptPKCS1v15(publicKey *rsa.PublicKey, secretMessage []byte) []byte {
	keySizeBytes := publicKey.N.BitLen() / 8
	paddedMessage := make([]byte, keySizeBytes)

	// Step: Padding
	paddedMessage[0], paddedMessage[1] = 0x00, 0x02
	for i := 2; i < keySizeBytes-len(secretMessage)-1; i++ {
		paddedMessage[i] = 0xff
	}
	paddedMessage[keySizeBytes-len(secretMessage)-1] = 0x00
	copy(paddedMessage[keySizeBytes-len(secretMessage):], secretMessage)

	// Step: Encryption
	messageBigInt := new(big.Int).SetBytes(paddedMessage)
	exponentBigInt := big.NewInt(int64(publicKey.E))
	ciphertextBigInt := new(big.Int).Exp(messageBigInt, exponentBigInt, publicKey.N)

	ciphertextBytes := make([]byte, keySizeBytes)
	ciphertextBigInt.FillBytes(ciphertextBytes)
	return ciphertextBytes
}
