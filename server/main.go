package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"robot-server/config"
	"robot-server/core"
	"robot-server/middleware"
	"robot-server/routes"
)

func main() {
	// Initialize system configuration
	core.LoadConfig()
	serverConfig := core.AppConfig

	// Generate vulnerable RSA certificate
	fmt.Printf("[*] Generating %d-bit VULNERABLE RSA certificate with %v...\n", serverConfig.RSAKeySize, serverConfig.SignatureAlgorithm)
	vulnerableCert, err := core.GenerateCert(serverConfig.CertFilePath, serverConfig.KeyFilePath, serverConfig.RSAKeySize, serverConfig.SignatureAlgorithm)
	if err != nil {
		log.Fatalf("Critical Error: Cert generation failed: %v", err)
	}

	// Setup application router
	appRouter := http.NewServeMux()
	routes.SetupRoutes(appRouter)

	// Wrap router with middleware
	loggingHandler := middleware.RequestLogger(appRouter)

	// Configure TLS with vulnerable certificate
	tlsConfig := config.GetTLSConfig()
	tlsConfig.Certificates = []tls.Certificate{vulnerableCert}

	// Initialize HTTPS server instance
	httpsServer := &http.Server{
		Addr:      ":" + serverConfig.ServerPort,
		Handler:   loggingHandler,
		TLSConfig: tlsConfig,
		// Disable HTTP/2 protocol
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	fmt.Printf("[*] Starting vulnerable server on https://0.0.0.0:%s\n", serverConfig.ServerPort)
	log.Fatal(httpsServer.ListenAndServeTLS("", ""))
}
