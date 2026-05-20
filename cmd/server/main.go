package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/config"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/store"
)

func main() {
	// Load the server configuration.
	cfg, err := config.Load("./config/config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Ensure that the data directory exists before initializing storage.

	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatal(err)
	}

	// Initialize the prototype JSON-backed storage layer.
	fileStore := store.NewJSONStore(cfg.DataDir, cfg.HMACSecret)

	// Initialize the audit logger used for security-relevant events.
	auditLogger := core.NewAuditLogger(filepath.Join(cfg.DataDir, "audit.log"))

	keyPath := filepath.Join(cfg.DataDir, "server_identity.key")
	var serverPriv ed25519.PrivateKey
	var serverPub ed25519.PublicKey

	// Load the persistent server identity key, or generate it on first startup.
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

	log.Printf("Server pubKey: %s", hex.EncodeToString(serverPub))

	// Wire the storage layer, audit logger, and server key into the API handler.
	handler := api.NewHandler(fileStore, *auditLogger, serverPriv)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	log.Printf("Starting Threshold Recovery server on %s", cfg.ServerPort)
	log.Printf("Data dir: %s", cfg.DataDir)

	certFile := "./certs/server.crt"
	keyFile := "./certs/server.key"

	// net/http expects the listen address in the form ":port".
	port := cfg.ServerPort
	if port != "" && port[0] != ':' {
		port = ":" + port
	}

	if err := http.ListenAndServeTLS(port, certFile, keyFile, mux); err != nil {
		log.Fatal(err)
	}
}
