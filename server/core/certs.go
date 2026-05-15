package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Certificate Generation
func GenerateCert(certFilePath, keyFilePath string, rsaKeySize int, sigAlgo x509.SignatureAlgorithm) (tls.Certificate, error) {
	// Key Generation
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Certificate Template
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ROBOT Simulation"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: sigAlgo,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-Signing
	certificateDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Directory Persistence
	os.MkdirAll(filepath.Dir(certFilePath), 0755)
	os.MkdirAll(filepath.Dir(keyFilePath), 0755)

	// File Export (PEM)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	os.WriteFile(certFilePath, certificatePEM, 0644)

	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	os.WriteFile(keyFilePath, privateKeyPEM, 0600)

	// Vulnerability Injection
	tlsCertificate := tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  &VulnerableKey{PrivateKey: privateKey},
	}

	return tlsCertificate, nil
}
