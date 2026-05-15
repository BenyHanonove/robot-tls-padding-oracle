package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func P_hash(secret, seed []byte, h func() hash.Hash, length int) []byte {
	result := make([]byte, length)
	a := seed
	for i := 0; i < length; {
		mac := hmac.New(h, secret)
		mac.Write(a)
		a = mac.Sum(nil)
		mac = hmac.New(h, secret)
		mac.Write(a)
		mac.Write(seed)
		chunk := mac.Sum(nil)
		copy(result[i:], chunk)
		i += len(chunk)
	}
	return result
}

func PRF(secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	return P_hash(secret, labelAndSeed, sha256.New, length)
}

func DeriveMasterSecret(pms, clientRandom, serverRandom []byte) []byte {
	seed := append(clientRandom, serverRandom...)
	return PRF(pms, "master secret", seed, 48)
}

type SessionKeys struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
}

func DeriveSessionKeys(masterSecret, clientRandom, serverRandom []byte) *SessionKeys {
	seed := append(serverRandom, clientRandom...)
	keyBlock := PRF(masterSecret, "key expansion", seed, 72)
	return &SessionKeys{
		ClientWriteKey: keyBlock[40:56],
		ServerWriteKey: keyBlock[56:72],
	}
}

func EncryptAESCBC(key, plaintext []byte, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	
	// Add Padding
	paddingLen := aes.BlockSize - (len(plaintext)+20)%aes.BlockSize
	if paddingLen == 0 { paddingLen = aes.BlockSize }
	
	padded := make([]byte, len(plaintext)+20+paddingLen)
	copy(padded, plaintext)
	// (Simplification: we skip real MAC calculation for the simulation body)
	// But we keep the structure: [Data] [DUMMY MAC (20)] [Padding]
	for i := len(plaintext) + 20; i < len(padded); i++ {
		padded[i] = byte(paddingLen - 1)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	
	return append(iv, ciphertext...)
}
