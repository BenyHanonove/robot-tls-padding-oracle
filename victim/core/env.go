package core

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

// Application environment configuration values
type VictimConfig struct {
	ServerURL  string
	TargetURL  string
	SnifferURL string
	VictimIP   string
	ServerIP   string
}

var Config *VictimConfig

// LoadConfig loads the victim configuration from .env and system environment.
func LoadConfig() {
	// load from .env file 
	_ = godotenv.Load()

	Config = &VictimConfig{
		ServerURL:  mustGetEnv("SERVER_URL"),
		TargetURL:  mustGetEnv("TARGET_URL"),
		SnifferURL: mustGetEnv("SNIFFER_URL"),
		VictimIP:   mustGetEnv("VICTIM_IP"),
		ServerIP:   mustGetEnv("SERVER_IP"),
	}
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("CRITICAL: Missing required environment variable: %s", key)
	}
	return val
}
