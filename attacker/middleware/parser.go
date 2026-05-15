package middleware

import "encoding/hex"

// Extract session ciphertext from packets
func ExtractCiphertext(capturedPackets []Packet) []byte {
	for _, packet := range capturedPackets {
		if packet.Plaintext == "ClientKeyExchange" {
			ciphertextBytes, _ := hex.DecodeString(packet.Data)
			return ciphertextBytes
		}
	}
	return nil
}

// Extract Handshake Randoms
func ExtractHandshakeRandoms(capturedPackets []Packet) (cRandom []byte, sRandom []byte) {
	for _, packet := range capturedPackets {
		if packet.Plaintext == "ClientHello" {
			cRandom, _ = hex.DecodeString(packet.Data)
		}
		if packet.Plaintext == "ServerHello" {
			sRandom, _ = hex.DecodeString(packet.Data)
		}
	}
	return
}
