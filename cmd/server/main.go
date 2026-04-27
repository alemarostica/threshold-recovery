package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

	// Server key infrastructure
	keyPath := filepath.Join(cfg.DataDir, "server_identity.key")
	var serverPriv ed25519.PrivateKey
	var serverPub ed25519.PublicKey

	// Does the key already exist?
	data, err := os.ReadFile(keyPath)
	if err == nil {
		// it does, load it
		privBytes, err := hex.DecodeString(string(data))
		if err != nil {
			log.Fatalf("Error decoding: %v", err)
		}

		if len(privBytes) != ed25519.PrivateKeySize {
			log.Fatalf("Private key not valid")
		}

		serverPriv = ed25519.PrivateKey(privBytes)
		serverPub = serverPriv.Public().(ed25519.PublicKey)
	} else {
		// it does not, generate one
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Error key generation: %v", err)
		}

		serverPriv = priv
		serverPub = pub

		// scrivo la chiave sul file
		err = os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0600)
		if err != nil {
			log.Fatalf("Failed to save the key: %v", err)
		}
	}

	// TODO: bruh decidere se inviarla o hardcodarla
	fmt.Printf("Server pubKey: %s\n", serverPub)

	// Logic and API
	// struct in internal/api/router.go
	handler := api.NewHandler(fileStore, *auditLogger, serverPriv)

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
	if err := http.ListenAndServeTLS(port, certFile, keyFile, mux); err != nil {
		log.Fatal(err)
	}
}
