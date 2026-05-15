package middleware

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

// Retrieve server RSA public key via handshake
func FetchServerPublicKey(targetURL string) (*rsa.PublicKey, error) {
	fmt.Printf("[NETWORK] Handshaking with %s for public key...\n", targetURL)

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn, err := tls.Dial("tcp", targetURL, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer tlsConn.Close()

	certificates := tlsConn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates received")
	}

	serverCert := certificates[0]
	publicKey, isRSA := serverCert.PublicKey.(*rsa.PublicKey)
	if !isRSA {
		return nil, fmt.Errorf("non-RSA key found: %T", serverCert.PublicKey)
	}

	fmt.Printf("[NETWORK] Extracted %d-bit RSA key\n", publicKey.N.BitLen())
	return publicKey, nil
}
