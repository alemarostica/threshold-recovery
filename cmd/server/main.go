package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/config"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/store"
)

func main() {
	// Load config
	// Config is a struct in internal/config/loader.go
	cfg, err := config.Load("./config/config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Try to create the dir if it doesn't exist
	// Do nothing if it exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatal(err)
	}

	// Simple JSON storage, struct in internal/store/json_store.go
	// Will it be good enough?
	fileStore := store.NewJSONStore(cfg.DataDir, cfg.HMACSecret)

	// Setup audit Logger
	auditLogger := core.NewAuditLogger(filepath.Join(cfg.DataDir, "audit.log"))

	// Logic and API
	// struct in internal/api/router.go
	verifier := &crypto.MockVerifier{}
	handler := api.NewHandler(fileStore, verifier, *auditLogger)

	// Router
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Start the actual server
	// Some logging
	log.Printf("Starting Threshold Recovery server on %s", cfg.ServerPort)
	log.Printf("Data dir: %s", cfg.DataDir)

	certFile := "./certs/server.crt"
	keyFile := "./certs/server.key"

	// Apparently port should be passed as :port, not port
	port := cfg.ServerPort
	if port != "" && port[0] != ':' {
		port = ":" + port
	}

	// TODO: to change with ListenAndServeTLS
	// As soon as ListenAndServe returns some error we exit and log a fatal error
	if err := http.ListenAndServeTLS(port, certFile, keyFile,  mux); err != nil {
		log.Fatal(err)
	}
}
