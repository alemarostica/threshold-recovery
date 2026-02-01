package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: participant <friend_id>")
		return
	}

	username := os.Args[1]
	serverURL := "http://localhost:8080"

	// Generate identity
	pubKey := make([]byte, 32)
	rand.Read(pubKey)

	fmt.Printf("Generating identity for %s...\n", username)
	fmt.Printf("Public key: %x\n", pubKey)

	// Register with server
	payload := map[string]interface{}{
		"id":         username,
		"public_key": pubKey,
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(serverURL+"/participants", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to connect to server: %s", resp.Status)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("Success! Registered on the server.")
		fmt.Println("Give this ID to you dealer friend.")
	} else {
		fmt.Printf("Failed: %s\n", resp.Status)
	}
}
