package middleware

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Session storage and formatting configuration
type SessionLogger struct {
	StorageDir string
	SessionID  string
}

// Initialize session output directory
func NewSessionLogger(baseDir string) *SessionLogger {
	sessionID := time.Now().Format("2006-01-02_15-04-05")
	os.MkdirAll(filepath.Join(baseDir, sessionID), 0755)
	return &SessionLogger{StorageDir: baseDir, SessionID: sessionID}
}

// Return absolute session path
func (logger *SessionLogger) SessionPath() string {
	return filepath.Join(logger.StorageDir, logger.SessionID)
}

// Record traffic to disk
func (logger *SessionLogger) LogTraffic(packets []Packet, fileName string, isDecrypted bool) {
	outputFile := filepath.Join(logger.SessionPath(), fileName)
	var logBuffer string

	for _, packet := range packets {
		logLine := fmt.Sprintf("[%s -> %s] ", packet.Source, packet.Dest)
		
		if packet.Type == "Handshake" {
			logLine += fmt.Sprintf("Handshake: %s\n", packet.Plaintext)
		} else {
			if isDecrypted {
				logLine += fmt.Sprintf("AppData [DECRYPTED]: %s\n", packet.Plaintext)
			} else {
				dataPreview := packet.Data
				if len(dataPreview) > 64 { dataPreview = dataPreview[:64] }
				logLine += fmt.Sprintf("AppData [ENCRYPTED %d bytes] | first 32 bytes: %s\n", packet.Size, dataPreview)
			}
		}
		logBuffer += logLine
	}

	os.WriteFile(outputFile, []byte(logBuffer), 0644)
	fmt.Printf("[LOGGER] Saved activity: %s\n", outputFile)
}
