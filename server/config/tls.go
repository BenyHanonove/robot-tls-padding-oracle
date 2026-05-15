package config

import (
	"crypto/tls"
	"robot-server/core"
)

// TLS Configuration
func GetTLSConfig() *tls.Config {
	serverConfig := core.AppConfig
	return &tls.Config{
		MinVersion:               serverConfig.TLSVersionMin,
		MaxVersion:               serverConfig.TLSVersionMax,
		PreferServerCipherSuites: serverConfig.PreferServerCiphers,
		CipherSuites:             serverConfig.VulnerableCiphers,
	}
}
