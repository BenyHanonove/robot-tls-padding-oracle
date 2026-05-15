package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// Logger Configuration
type SnifferLogger struct {
	SnifferEndpoint string
	VictimAddress   string
	ServerAddress   string
}

// Initialization
func NewSnifferLogger(snifferURL, victimIP, serverIP string) *SnifferLogger {
	return &SnifferLogger{
		SnifferEndpoint: snifferURL,
		VictimAddress:   victimIP,
		ServerAddress:   serverIP,
	}
}

// Packet Transmission
func (logger *SnifferLogger) LogPacket(source, destination, protocolType, plaintextPayload, hexEncodedData string) {
	// Payload Construction
	packetMessage := map[string]interface{}{
		"src":  source,
		"dst":  destination,
		"type": protocolType,
		"size": len(hexEncodedData) / 2,
		"data": hexEncodedData,
	}

	// For Handshake packets, we keep the label (like "ClientHello") in a 'plaintext' field 
	// just so the attacker knows what the packet is, but for AppData, we SEND NOTHING.
	if protocolType == "Handshake" {
		packetMessage["plaintext"] = plaintextPayload
	}

	// Remote Reporting
	serializedPayload, _ := json.Marshal(packetMessage)
	http.Post(logger.SnifferEndpoint, "application/json", bytes.NewBuffer(serializedPayload))
}
