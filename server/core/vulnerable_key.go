package core

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

// RSA padding oracle wrapper
type VulnerableKey struct {
	*rsa.PrivateKey
}

// Decrypt and validate padding (VULNERABLE VERSION)
func (key *VulnerableKey) Decrypt(randomSource io.Reader, ciphertext []byte, options crypto.DecrypterOpts) (plaintext []byte, err error) {
	// Step 1: Perform RAW RSA decryption (m = c^d mod n)
	c := new(big.Int).SetBytes(ciphertext)
	m := new(big.Int).Exp(c, key.D, key.N)
	
	// Step 2: Convert to bytes (ensure leading zeros are preserved)
	keySizeBytes := (key.N.BitLen() + 7) / 8
	mBytes := make([]byte, keySizeBytes)
	m.FillBytes(mBytes)

	// Step 3: VULNERABLE PADDING CHECK
	// A real server would use constant-time checks, but we are being "lazy"
	if mBytes[0] != 0x00 || mBytes[1] != 0x02 {
		fmt.Printf("[ORACLE] Padding Incorrect (Missing 00 02)! Resetting...\n")
		// We panic to simulate a connection reset/alert that the attacker can see
		panic("ROBOT_ORACLE_VULNERABILITY: Bad Padding")
	}

	fmt.Printf("[ORACLE] Padding Correct. Proceeding with handshake.\n")
	
	// Return the real decryption result so the handshake can proceed if padding is good
	return key.PrivateKey.Decrypt(randomSource, ciphertext, options)
}
