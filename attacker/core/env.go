package core

import (
	"log"
	"os"
	"strconv"
	"github.com/joho/godotenv"
)

// Attacker environment configuration structure
type AttackerConfig struct {
	TargetHost        string
	TargetPort        string
	AttackConcurrency int
	OracleTimeoutMS   int
	ServerCertPath    string
	DebugMode         bool
}

// Global attacker configuration instance
var Config *AttackerConfig

// Initialize configuration from environment
func LoadConfig() {
	_ = godotenv.Load()

	Config = &AttackerConfig{
		TargetHost:        mustGetEnv("TARGET_HOST"),
		TargetPort:        mustGetEnv("TARGET_PORT"),
		AttackConcurrency: mustGetEnvInt("ATTACK_CONCURRENCY"),
		OracleTimeoutMS:   mustGetEnvInt("ORACLE_TIMEOUT_MS"),
		ServerCertPath:    mustGetEnv("SERVER_CERT_PATH"),
		DebugMode:         os.Getenv("DEBUG_MODE") == "true",
	}
}

// Return formatted target address
func (config *AttackerConfig) TargetURL() string {
	return config.TargetHost + ":" + config.TargetPort
}

// Required environment variable lookup
func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("CRITICAL: Missing variable: %s", key)
	}
	return value
}

// Integer environment variable lookup
func mustGetEnvInt(key string) int {
	stringValue := mustGetEnv(key)
	intValue, err := strconv.Atoi(stringValue)
	if err != nil {
		log.Fatalf("CRITICAL: Invalid integer: %s", stringValue)
	}
	return intValue
}
