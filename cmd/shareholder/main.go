package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shareholder <wallet_pubkey_hex> <friend_id>")
		return
	}

	pubKeyBytes, err := hex.DecodeString(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid wallet public key hex: %v", err)
	}
	friendPubKeyBase64 := os.Args[2]
	friendPubKey, err := base64.StdEncoding.DecodeString(friendPubKeyBase64)
	if err != nil {
		log.Fatalf("Invalid friend public key (must be base64): %v", err)
	}

	fmt.Printf("Checking mailbox for %s...\n", friendPubKey)

	payload := map[string]interface{}{
		"public_key":     pubKeyBytes,
		"friend_pub_key": friendPubKey,
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post("http://localhost:8080/mailbox/pickup", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Network request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBlob, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read server responde: %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		saveShare(friendPubKey, bodyBlob)
	case http.StatusForbidden:
		fmt.Println("\nACCESS DENIED")
		fmt.Printf("Reason: %s\n", strings.TrimSpace(string(bodyBlob)))
		fmt.Println("The user is likely still active. Recovery is not yet permitted.")
		os.Exit(1)
	case http.StatusNotFound:
		fmt.Println("\nNOT FOUND")
		fmt.Printf("Server message: %s\n", strings.TrimSpace(string(bodyBlob)))
		fmt.Println("Check the wallet public key and friend ID.")
		os.Exit(1)
	default:
		fmt.Printf("\n Server returned error %d: %s\n", resp.StatusCode, strings.TrimSpace(string(bodyBlob)))
		os.Exit(1)
	}
}

func saveShare(friendID []byte, data []byte) {
	filename := fmt.Sprintf("share_%s.bin", friendID)
	err := os.WriteFile(filename, data, 0600)
	if err != nil {
		log.Fatalf("Failed to write file to disk: %v", err)
	}

	fmt.Println("SUCCESS")
	fmt.Printf("Encrypted share retrieved (%d bytes).\n", len(data))
	fmt.Printf("Saved to: %s\n", filename)
	fmt.Println("Keep this file safe! It is required to reconstruct the key.")
}
