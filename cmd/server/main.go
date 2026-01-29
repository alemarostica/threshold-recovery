package main

import (
	"log"
	"net/http"
	"os"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/config"
	// "threshold-recovery/internal/core"
	"threshold-recovery/internal/store"
)

func main() {
	// Load config
	cfg, err := config.Load("./config/config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Try to make the dir if it doesn't exist
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatal(err)
	}

	// Simple JSON storage
	// Will it be good enough?
	fileStore := store.NewJSONStore(cfg.DataDir)

	// Logic and API
	handler := api.NewHandler(fileStore)

	// Router
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Start the actual server
	log.Printf("Starting Threshold Recovery server on %s", cfg.ServerPort)
	log.Printf("Data dir: %s", cfg.DataDir)

	port := cfg.ServerPort
	if port != "" && port[0] != ':' {
		port = ":" + port
	}

	// TODO: to change with ListenAndServeTLS
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}
