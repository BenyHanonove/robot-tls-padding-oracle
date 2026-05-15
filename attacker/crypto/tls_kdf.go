package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
)

// P_hash implements the P_hash function defined in RFC 5246
func P_hash(secret, seed []byte, h func() hash.Hash, length int) []byte {
	result := make([]byte, length)
	hObj := h()
	_ = hObj // Ensure use

	// A(0) = seed
	a := seed
	
	for i := 0; i < length; {
		// A(i) = HMAC_hash(secret, A(i-1))
		mac := hmac.New(h, secret)
		mac.Write(a)
		a = mac.Sum(nil)
		
		// HMAC_hash(secret, A(i) + seed)
		mac = hmac.New(h, secret)
		mac.Write(a)
		mac.Write(seed)
		chunk := mac.Sum(nil)
		
		copy(result[i:], chunk)
		i += len(chunk)
	}
	return result
}

// PRF implements the TLS 1.2 Pseudo-Random Function
func PRF(secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	return P_hash(secret, labelAndSeed, sha256.New, length)
}

// DeriveMasterSecret calculates the 48-byte Master Secret
func DeriveMasterSecret(pms, clientRandom, serverRandom []byte) []byte {
	seed := append(clientRandom, serverRandom...)
	return PRF(pms, "master secret", seed, 48)
}

// SessionKeys holds the keys derived for a TLS session
type SessionKeys struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteMAC []byte
	ServerWriteMAC []byte
}

// DeriveSessionKeys expands the master secret into specific encryption keys
func DeriveSessionKeys(masterSecret, clientRandom, serverRandom []byte) *SessionKeys {
	seed := append(serverRandom, clientRandom...)
	// For AES-128-CBC-SHA:
	// 2 x 20 bytes (MAC keys) + 2 x 16 bytes (AES keys) = 72 bytes
	keyBlock := PRF(masterSecret, "key expansion", seed, 72)
	
	return &SessionKeys{
		ClientWriteMAC: keyBlock[0:20],
		ServerWriteMAC: keyBlock[20:40],
		ClientWriteKey: keyBlock[40:56],
		ServerWriteKey: keyBlock[56:72],
	}
}

// DecryptAESCBC decrypts a TLS 1.2 AES-CBC record
func DecryptAESCBC(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize+1 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// TLS 1.2 uses an explicit IV at the start of the record
	iv := ciphertext[:aes.BlockSize]
	actualCiphertext := ciphertext[aes.BlockSize:]

	if len(actualCiphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(actualCiphertext))
	mode.CryptBlocks(plaintext, actualCiphertext)

	// Strip Padding and MAC (Simplified for demonstration)
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	paddingLen := int(plaintext[len(plaintext)-1])
	contentEnd := len(plaintext) - paddingLen - 1 - 20
	
	if contentEnd < 0 {
		return nil, fmt.Errorf("decryption failed or invalid padding")
	}

	return plaintext[:contentEnd], nil
}
