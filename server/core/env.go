package core

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Server environment configuration structure
type Config struct {
	TLSVersion          string
	TLSVersionMin       uint16
	TLSVersionMax       uint16
	VulnerableCiphers   []uint16
	ServerPort          string
	RSAKeySize          int
	CertFilePath        string
	KeyFilePath         string
	PreferServerCiphers bool
	SignatureAlgorithm  x509.SignatureAlgorithm
}

// Global server configuration instance
var AppConfig *Config

// Initialize configuration from environment
func LoadConfig() {
	_ = godotenv.Load()

	AppConfig = &Config{
		TLSVersion:          mustGetEnv("TLS_VERSION"),
		ServerPort:          mustGetEnv("SERVER_PORT"),
		CertFilePath:        mustGetEnv("CERT_FILE_PATH"),
		KeyFilePath:         mustGetEnv("KEY_FILE_PATH"),
		RSAKeySize:          mustGetEnvInt("RSA_KEY_SIZE"),
		PreferServerCiphers: mustGetEnv("PREFER_SERVER_CIPHERS") == "true",
	}

	AppConfig.TLSVersionMin = parseTLSVersion(mustGetEnv("TLS_VERSION_MIN"))
	AppConfig.TLSVersionMax = parseTLSVersion(mustGetEnv("TLS_VERSION_MAX"))

	ciphers := mustGetEnv("VULNERABLE_CIPHER_SUITE")
	for _, c := range strings.Split(ciphers, ",") {
		cipherName := strings.TrimSpace(c)
		if cipherID, ok := cipherMap[cipherName]; ok {
			AppConfig.VulnerableCiphers = append(AppConfig.VulnerableCiphers, cipherID)
		} else {
			log.Fatalf("CRITICAL ERROR: Unknown cipher suite: %s", cipherName)
		}
	}

	sigAlgo := mustGetEnv("SIGNATURE_ALGORITHM")
	if algo, ok := signatureAlgorithmMap[sigAlgo]; ok {
		AppConfig.SignatureAlgorithm = algo
	} else {
		log.Fatalf("CRITICAL ERROR: Unknown signature algorithm: %s", sigAlgo)
	}
}

// Required environment variable lookup
func mustGetEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		log.Fatalf("CRITICAL ERROR: Missing variable: %s", key)
	}
	return value
}

// Integer environment variable lookup
func mustGetEnvInt(key string) int {
	stringValue := mustGetEnv(key)
	intValue, err := strconv.Atoi(stringValue)
	if err != nil {
		log.Fatalf("CRITICAL ERROR: Invalid integer: %s", stringValue)
	}
	return intValue
}

// Map string to TLS version
func parseTLSVersion(versionString string) uint16 {
	switch versionString {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		log.Fatalf("CRITICAL ERROR: Unsupported version: %s", versionString)
		return 0
	}
}

// Map names to cipher IDs
var cipherMap = map[string]uint16{
	"TLS_RSA_WITH_AES_128_CBC_SHA":    tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":    tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
}

var signatureAlgorithmMap = map[string]x509.SignatureAlgorithm{
	"SHA1-RSA":   x509.SHA1WithRSA,
	"SHA256-RSA": x509.SHA256WithRSA,
	"SHA384-RSA": x509.SHA384WithRSA,
	"SHA512-RSA": x509.SHA512WithRSA,
}
